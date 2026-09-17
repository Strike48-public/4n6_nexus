"""Role-scoped authorization wired through the server boundary (SFE-l7mp).

The guard-level role gate is unit-tested in test_mcp_role_allowlists.py. This
proves the gate is actually REACHABLE in production: run_tool / start_job map
the caller's ``agent`` identity to a role and pass it to ``ToolGuard.check``, so
a role violation is refused and audited as ``tool_blocked`` -- identical shape to
an arg violation, on the same correlated thread.

Backward-compat: an agent identity that is a known role (memory_analyst, ...) is
enforced; the security boundary stays in ONE place (the server).
"""

from __future__ import annotations

import pytest

from sift_find_evil.mcp.guardrails import GuardrailViolation
from sift_find_evil.mcp.jobs import JobRunner, JobStore
from sift_find_evil.mcp.server import EvidenceMCPServer


@pytest.fixture
def evidence_root(tmp_path):
    root = tmp_path / "evidence"
    root.mkdir()
    (root / "memory.raw").write_bytes(b"fake mem")
    return root


@pytest.fixture
def server(tmp_path, evidence_root):
    runner = JobRunner(store=JobStore(root=tmp_path / "jobs"), spawn=lambda a, **k: 1)
    return EvidenceMCPServer(
        case_id="INC-ROLE-001",
        evidence_root=evidence_root,
        audit_path=tmp_path / "audit.jsonl",
        examiner="jtomek",
        job_runner=runner,
    )


def _vol_args(evidence_root):
    return ["-f", str(evidence_root / "memory.raw"), "-r", "json", "windows.pslist"]


# -- run_tool enforces the caller's role ------------------------------------


def test_run_tool_blocks_wrong_role_and_audits(server, evidence_root):
    # network_analyst calling volatility: valid args, unauthorized role.
    with pytest.raises(GuardrailViolation):
        server.run_tool(
            "volatility",
            _vol_args(evidence_root),
            agent="network_analyst",
            correlation_id="corr-role",
        )
    blocked = [
        e
        for e in server.audit_logger.get_recent(limit=10)
        if e.action == "tool_blocked"
    ]
    assert blocked, "a role-denied run_tool must be logged as tool_blocked"
    assert blocked[0].agent == "network_analyst"
    assert blocked[0].correlation_id == "corr-role"


def test_run_tool_allows_authorized_role(server, evidence_root, monkeypatch):
    # memory_analyst -> volatility is authorized: the guard must NOT block it.
    # Stub execution so the test never shells out to a real `vol`.
    monkeypatch.setattr(
        server,
        "_execute",
        lambda tool, args: {
            "success": True,
            "stdout": "[]",
            "stderr": "",
            "exit_code": 0,
            "duration_ms": 1,
        },
    )
    result = server.run_tool(
        "volatility",
        _vol_args(evidence_root),
        agent="memory_analyst",
        correlation_id="corr-ok",
    )
    assert result["exit_code"] == 0
    assert "entry_id" in result


def test_start_job_blocks_wrong_role_and_stages_nothing(server, evidence_root):
    store = server.job_runner.store
    with pytest.raises(GuardrailViolation):
        server.start_job(
            tool="volatility",
            args=_vol_args(evidence_root),
            agent="network_analyst",  # not authorized for volatility
            correlation_id="corr-role-job",
        )
    assert list(store.root.glob("*")) == [] or not store.root.exists()
    # The denied detached call must be audited as tool_blocked, exactly like the
    # synchronous run_tool boundary (same correlated thread, same agent).
    blocked = [
        e
        for e in server.audit_logger.get_recent(limit=10)
        if e.action == "tool_blocked"
    ]
    assert blocked, "a role-denied start_job must be logged as tool_blocked"
    assert blocked[0].agent == "network_analyst"
    assert blocked[0].correlation_id == "corr-role-job"


# -- an unknown agent identity must not silently bypass the gate ------------


def test_verifier_tiebreaker_role_is_allowed(server, evidence_root, monkeypatch):
    # The verifier's read-only tiebreaker (psscan via volatility) is authorized.
    monkeypatch.setattr(
        server,
        "_execute",
        lambda tool, args: {
            "success": True,
            "stdout": "[]",
            "stderr": "",
            "exit_code": 0,
            "duration_ms": 1,
        },
    )
    result = server.run_tool(
        "volatility",
        _vol_args(evidence_root),
        agent="verifier",
        correlation_id="corr-verify",
    )
    assert result["exit_code"] == 0


def test_verifier_cannot_list_disk_image(server, evidence_root):
    # sleuthkit (fls) is NOT in the verifier's tiebreaker set -> blocked.
    with pytest.raises(GuardrailViolation):
        server.run_tool(
            "sleuthkit",
            ["-r", "-o", "63", str(evidence_root / "memory.raw")],
            agent="verifier",
            correlation_id="corr-verify-deny",
        )


# -- dispatch roles manage the job queue for any tool (review finding #1) ---
# start_job's FastMCP endpoint defaults agent="orchestrator" (a dispatch role
# that owns no forensic tool). A detached job under that DEFAULT must NOT be
# denied -- job management is the dispatch role's whole function. Regression
# guard for the "green but untested default path" gap.


def test_start_job_default_dispatch_agent_is_allowed(server, evidence_root):
    # Exactly the FastMCP start_job endpoint default (agent="orchestrator").
    result = server.start_job(
        tool="volatility",
        args=_vol_args(evidence_root),
        agent="orchestrator",
        correlation_id="corr-dispatch-job",
    )
    assert "job_id" in result  # staged, not denied
    assert result["state"]


def test_start_job_dispatch_still_guards_payload_args(server):
    # A dispatch role manages the queue, but the PAYLOAD is still hard-guarded:
    # an out-of-root path is refused regardless of the (privileged) role.
    with pytest.raises(GuardrailViolation):
        server.start_job(
            tool="volatility",
            args=["-f", "/etc/shadow", "-r", "json", "windows.pslist"],
            agent="orchestrator",
            correlation_id="corr-dispatch-escape",
        )


def test_start_job_analyst_still_domain_scoped(server, evidence_root):
    # The detached path is NOT a role bypass for an ANALYST: a network_analyst
    # cannot background a volatility job any more than it can run one live.
    with pytest.raises(GuardrailViolation):
        server.start_job(
            tool="volatility",
            args=_vol_args(evidence_root),
            agent="network_analyst",
            correlation_id="corr-analyst-job-deny",
        )
