"""Tests that the cross-source correlator is WIRED into the orchestrator.

The correlator primitive (sift_find_evil/correlation/cross_source.py) landed and
was unit-tested standalone (PR #75); this proves the live orchestrator actually
builds a ``CrossSourceInput`` from VERIFIED findings, runs the discrepancy pass,
and renders each discrepancy into the report with its citations + MITRE mapping.

The demo (02_ransomware) carries memory + disk + network fixtures. Its memory
shows a live connection to 203.0.113.66 (crypt_engine.exe / PID 6666) that NO DNS
query in the capture resolved -> exactly one PHANTOM_CONNECTION discrepancy. It
must NOT manufacture a GHOST_PROCESS: crypt_engine.exe IS on disk (MFT), and the
build must not feed benign raw pslist names (svchost/explorer) that the sparse
synthetic MFT would falsely flag.

RED-first: before this change run_demo_investigation emitted no
``cross_source_discrepancies`` key.
"""

from __future__ import annotations

from pathlib import Path

from sift_find_evil.orchestration import InvestigationOrchestrator


def _run(tmp_path):
    orch = InvestigationOrchestrator(
        case_id="INC-XS-001", audit_path=tmp_path / "audit.jsonl"
    )
    return orch.run_demo_investigation()


# -- the correlator runs and surfaces the phantom connection ----------------


def test_report_carries_cross_source_discrepancies_block(tmp_path):
    report = _run(tmp_path)
    assert "cross_source_discrepancies" in report, "correlator not wired into report"
    assert isinstance(report["cross_source_discrepancies"], list)


def test_demo_surfaces_the_phantom_connection(tmp_path):
    report = _run(tmp_path)
    phantom = [
        d
        for d in report["cross_source_discrepancies"]
        if d["type"] == "phantom_connection"
    ]
    assert len(phantom) == 1, f"expected 1 phantom connection, got {phantom}"
    d = phantom[0]
    assert d["subject"] == "203.0.113.66"
    assert "T1071" in d["mitre"]
    # Renders its citations so an examiner can trace the discrepancy.
    assert d["memory_evidence"], "phantom discrepancy must cite its memory evidence"
    assert d["needs_verification"] is True


def test_demo_does_not_manufacture_a_ghost_process(tmp_path):
    # crypt_engine.exe is live in memory AND on disk (MFT), so it is not a ghost;
    # and benign raw pslist names (svchost/explorer) must never be fed as memory
    # suspects against the sparse synthetic MFT (that would be a false ghost).
    report = _run(tmp_path)
    ghosts = [
        d for d in report["cross_source_discrepancies"] if d["type"] == "ghost_process"
    ]
    assert ghosts == [], f"unexpected ghost-process discrepancies: {ghosts}"


def test_no_uninstalled_execution_without_a_registry_source(tmp_path):
    # The demo has no registry fixture, so registry_installed is None and the
    # UNINSTALLED_EXECUTION check must be skipped (not false-fire on every exe).
    report = _run(tmp_path)
    uninstalled = [
        d
        for d in report["cross_source_discrepancies"]
        if d["type"] == "uninstalled_execution"
    ]
    assert uninstalled == []


# -- the CrossSourceInput is built faithfully from verified findings --------


def test_cross_source_input_uses_verified_findings_not_raw_fixtures(tmp_path):
    orch = InvestigationOrchestrator(
        case_id="INC-XS-BUILD", audit_path=tmp_path / "a.jsonl"
    )
    orch.run_demo_investigation()  # run for its side effect: builds the input
    inp = orch._last_cross_source_input
    assert inp is not None, "_build_cross_source_input was never called"
    # Memory suspects come from verified memory findings (crypt_engine.exe), NOT
    # the raw pslist (which also holds benign svchost.exe/explorer.exe).
    assert inp.memory_process_names is not None
    assert "svchost.exe" not in inp.memory_process_names
    assert "explorer.exe" not in inp.memory_process_names
    # The foreign IP the memory finding asserts is present for the phantom check.
    assert "203.0.113.66" in (inp.memory_foreign_ips or [])
    # Disk was consulted, so disk_artifact_names is a list (search space), and it
    # includes the on-disk executable that keeps crypt_engine.exe from ghosting.
    assert inp.disk_artifact_names is not None
    assert any("crypt_engine.exe" in d for d in inp.disk_artifact_names)
    # No registry fixture in the demo -> registry source is None (not []).
    assert inp.registry_installed is None
    assert inp.verified_finding_count >= 1


def test_correlator_gate_respected_when_no_memory_findings(tmp_path):
    # A disk-only scenario (no memory/network fixtures) must yield an empty
    # discrepancy list, not an error: the correlator gate requires a memory
    # source. 01_clean_baseline has no memory_fixtures/.
    orch = InvestigationOrchestrator(
        case_id="INC-XS-DISK",
        audit_path=tmp_path / "a.jsonl",
        scenario_dir=Path("scenarios/synthetic/01_clean_baseline"),
    )
    report = orch.run_demo_investigation()
    assert report["cross_source_discrepancies"] == []
    # Memory was NOT consulted, so its suspect sources are None (checks skipped).
    assert orch._last_cross_source_input.memory_process_names is None
    assert orch._last_cross_source_input.memory_foreign_ips is None


def test_memory_consulted_but_no_verified_findings_is_empty_not_none(tmp_path):
    """Consulted-but-clean memory must be [] (checks run), never None (skipped).

    Regression guard for the memory-consulted-vs-found distinction: if the input
    were built by inferring "memory ran" from verified memory findings, a run
    whose memory findings all failed verification would wrongly report the memory
    sources as None and skip the ghost/phantom checks entirely. We simulate that
    by clearing verified memory findings after a real memory analyst run and
    rebuilding the input directly.
    """
    orch = InvestigationOrchestrator(
        case_id="INC-XS-CLEANMEM", audit_path=tmp_path / "a.jsonl"
    )
    orch.run_demo_investigation()
    assert orch._memory_consulted is True
    # Rebuild with an empty verified list (no verified memory findings survived):
    # memory was still consulted, so the suspect lists must be [] not None.
    rebuilt = orch._build_cross_source_input([])
    assert rebuilt.memory_process_names == []
    assert rebuilt.memory_foreign_ips == []


# -- integrity block reports the discrepancy count --------------------------


def test_integrity_block_reports_cross_source_count(tmp_path):
    report = _run(tmp_path)
    assert report["integrity"]["cross_source_discrepancies"] == len(
        report["cross_source_discrepancies"]
    )
    assert report["integrity"]["cross_source_discrepancies"] >= 1
