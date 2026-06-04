"""End-to-end multi-agent orchestration -> traceable A2A log (SFE-h5z).

This is the deterministic, judge-reproducible harness (Option A). It drives the
agent flow in-process -- orchestrator dispatches triage, analysts emit findings
through the MCP audit boundary, the verifier challenges them -- and writes a single
correlated A2A audit log. Every finding must be traceable back to the tool
executions that produced it via AuditLogger.trace().

The real Claude Code subagents (Option B) reuse the same agent definitions and MCP
server for the recorded demo; this harness guarantees the reproducible artifact.
"""

from __future__ import annotations

from sift_find_evil.orchestration import InvestigationOrchestrator


def test_run_produces_single_correlated_a2a_log(tmp_path):
    audit = tmp_path / "audit.jsonl"
    orch = InvestigationOrchestrator(
        case_id="INC-2026-001",
        audit_path=audit,
        examiner="jtomek",
    )

    report = orch.run_demo_investigation()

    assert audit.exists()
    # The log must contain each A2A record type.
    actions = {e.action for e in orch.server.audit_logger.get_recent(limit=1000)}
    assert "agent_message" in actions
    assert "tool_invocation" in actions
    assert "finding_emitted" in actions
    assert "verification" in actions

    # All entries share one correlation thread (single investigation).
    corr_ids = {
        e.correlation_id
        for e in orch.server.audit_logger.get_recent(limit=1000)
        if e.correlation_id
    }
    assert len(corr_ids) == 1

    assert report["case_id"] == "INC-2026-001"
    assert report["findings"], "investigation should surface at least one finding"


def test_every_finding_traces_to_its_tool_executions(tmp_path):
    orch = InvestigationOrchestrator(
        case_id="INC-2026-001",
        audit_path=tmp_path / "audit.jsonl",
        examiner="jtomek",
    )
    report = orch.run_demo_investigation()

    for finding in report["findings"]:
        thread = orch.server.audit_logger.trace(finding["finding_id"])
        assert thread, f"{finding['finding_id']} must be traceable"
        # The trace must include at least one tool execution and a verification.
        actions = [e.action for e in thread]
        assert "tool_invocation" in actions
        assert "finding_emitted" in actions


def test_self_correction_sequence_is_present(tmp_path):
    """The demo must contain at least one visible self-correction (the tiebreaker)."""
    orch = InvestigationOrchestrator(
        case_id="INC-2026-001",
        audit_path=tmp_path / "audit.jsonl",
        examiner="jtomek",
    )
    orch.run_demo_investigation()

    verifications = [
        e
        for e in orch.server.audit_logger.get_recent(limit=1000)
        if e.action == "verification"
    ]
    assert verifications
    # At least one verification resolved a contradiction (confidence moved).
    resolved = [
        v
        for v in verifications
        if v.details.get("verdict")
        in ("contradiction_resolved", "contradiction_detected")
    ]
    assert resolved, "demo must show a self-correction (contradiction handling)"


def test_blocked_tool_attempt_is_recorded(tmp_path):
    """A guardrail denial during the run is captured for the audit trail."""
    orch = InvestigationOrchestrator(
        case_id="INC-2026-001",
        audit_path=tmp_path / "audit.jsonl",
        examiner="jtomek",
    )
    orch.run_demo_investigation(include_bypass_attempt=True)

    blocked = [
        e
        for e in orch.server.audit_logger.get_recent(limit=1000)
        if e.action == "tool_blocked"
    ]
    assert blocked, "a guardrail bypass attempt should be logged as tool_blocked"
