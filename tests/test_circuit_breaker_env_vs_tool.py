"""Circuit breaker counts tool failures, not environment failures (SFE-zydh).

The circuit breaker exists to halt a run when a TOOL misbehaves (repeated
crashes/errors from the tool itself). An ENVIRONMENT failure -- the tool binary
is not installed, the run timed out, a detached payload was unreadable -- means
the tool never actually ran; the guardrail's path-containment check passed and
nothing about the tool is wrong. Counting those toward the breaker would let ~3
unrelated config issues spuriously open it and halt an investigation.

This pins the shared classification across BOTH execution paths:
  * synchronous ``run_tool`` (``_execute`` returns exit_code=None for timeout /
    tool-not-found), and
  * the detached reconcile path (``_reconcile_terminal``; the worker records
    exit_code=None with no result for spawn/not-found failures).

Contract keys on the exit code: NEVER_RAN_EXIT_CODE (which is ``None`` -- the
ABSENCE of a code) -> environment failure that does NOT count but is still
AUDITED; 0 -> success (resets the breaker); any INTEGER != 0, including a
signal-death negative (SIGHUP -> -1, SIGSEGV -> -11), -> the tool RAN and failed,
so it counts. Keying "never ran" on None rather than a magic negative is
deliberate and collision-proof: -1 is also SIGHUP, so a -1 sentinel would
misclassify a SIGHUP-killed tool as never-run. A blocked/denied call is a
separate concern (guardrail rejection) and is unaffected.

RED-first: before the fix both paths called record_failure() for ANY non-success,
so N consecutive environment failures opened the breaker.
"""

from __future__ import annotations

import pytest

from sift_find_evil.mcp.guardrails import CircuitBreakerOpen
from sift_find_evil.mcp.jobs import NEVER_RAN_EXIT_CODE, JobRunner, JobStore
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
        case_id="INC-CB-001",
        evidence_root=evidence_root,
        audit_path=tmp_path / "audit.jsonl",
        examiner="jtomek",
        job_runner=runner,
    )


def _args(evidence_root):
    return ["-f", str(evidence_root / "memory.raw"), "-r", "json", "windows.pslist"]


# -- synchronous path -------------------------------------------------------


def test_env_failure_does_not_count_toward_breaker_sync(
    server, evidence_root, monkeypatch
):
    """Repeated tool-not-found (never ran) must NOT open the breaker on run_tool."""

    def not_found(tool, args):
        return {
            "success": False,
            "stdout": "",
            "stderr": f"Tool not found: {tool}",
            "exit_code": NEVER_RAN_EXIT_CODE,  # None -> never ran
            "duration_ms": 1,
        }

    monkeypatch.setattr(server, "_execute", not_found)
    args = _args(evidence_root)
    # Far more than max_consecutive_failures (3): none may count.
    for _ in range(6):
        server.run_tool("volatility", args, agent="memory_analyst", correlation_id="c")
    assert server.guard.failure_count == 0, "environment failures must not count"
    assert server.guard.circuit_open is False
    # ...but each attempt is still audited (traceability is not sacrificed).
    invs = [e for e in server.audit_logger._read_all() if e.action == "tool_invocation"]
    assert len(invs) == 6


def test_genuine_tool_failure_still_counts_sync(server, evidence_root, monkeypatch):
    """A tool that RAN and exited non-zero (exit 1) still trips the breaker."""

    def failing(tool, args):
        return {
            "success": False,
            "stdout": "",
            "stderr": "boom",
            "exit_code": 1,
            "duration_ms": 1,
        }

    monkeypatch.setattr(server, "_execute", failing)
    args = _args(evidence_root)
    for _ in range(3):
        server.run_tool("volatility", args, agent="memory_analyst", correlation_id="c")
    with pytest.raises(CircuitBreakerOpen):
        server.run_tool("volatility", args, agent="memory_analyst", correlation_id="c")


def test_success_resets_breaker_sync(server, evidence_root, monkeypatch):
    """A success after some genuine failures resets the consecutive count."""
    outcomes = iter([1, 1, 0])  # fail, fail, then succeed

    def variable(tool, args):
        code = next(outcomes)
        return {
            "success": code == 0,
            "stdout": "[]" if code == 0 else "",
            "stderr": "" if code == 0 else "boom",
            "exit_code": code,
            "duration_ms": 1,
        }

    monkeypatch.setattr(server, "_execute", variable)
    args = _args(evidence_root)
    for _ in range(3):
        server.run_tool("volatility", args, agent="memory_analyst", correlation_id="c")
    assert server.guard.failure_count == 0, "a success must reset the breaker"


# -- detached path ----------------------------------------------------------


def _start(server, evidence_root):
    return server.start_job(
        "volatility", _args(evidence_root), agent="memory_analyst", correlation_id="c"
    )["job_id"]


def test_env_failure_does_not_count_toward_breaker_detached(server, evidence_root):
    """A detached spawn/not-found failure (never ran, no result) must NOT count."""
    for _ in range(6):
        job_id = _start(server, evidence_root)
        server.job_runner.store.mark_failed(
            job_id, exit_code=NEVER_RAN_EXIT_CODE, error="tool not found: volatility"
        )
        server.poll_job(job_id, agent="memory_analyst", correlation_id="c")
    assert server.guard.failure_count == 0, "detached env failures must not count"
    assert server.guard.circuit_open is False


def test_genuine_tool_failure_counts_detached(server, evidence_root):
    """A detached tool that RAN and exited non-zero (exit 1) counts toward the breaker."""
    for _ in range(3):
        job_id = _start(server, evidence_root)
        server.job_runner.store.mark_failed(job_id, exit_code=1, error="exited 1")
        server.poll_job(job_id, agent="memory_analyst", correlation_id="c")
    assert server.guard.failure_count == 3, "genuine detached tool failures count"
    assert server.guard.circuit_open is True


# -- signal-killed tools are tool misbehavior, NOT environment failures -----


def test_signal_killed_tool_counts_toward_breaker_sync(
    server, evidence_root, monkeypatch
):
    """A tool killed by a signal (e.g. SIGSEGV -> exit -11) is tool misbehavior.

    subprocess surfaces a signal death as a NEGATIVE returncode; a repeatedly
    segfaulting/OOM-killed tool IS misbehaving and must trip the breaker. "Never
    ran" is keyed on the ABSENCE of a code (None), so a real negative code counts.
    """

    def segfault(tool, args):
        return {
            "success": False,
            "stdout": "",
            "stderr": "Segmentation fault",
            "exit_code": -11,  # killed by SIGSEGV
            "duration_ms": 5,
        }

    monkeypatch.setattr(server, "_execute", segfault)
    args = _args(evidence_root)
    for _ in range(3):
        server.run_tool("volatility", args, agent="memory_analyst", correlation_id="c")
    with pytest.raises(CircuitBreakerOpen):
        server.run_tool("volatility", args, agent="memory_analyst", correlation_id="c")


def test_sighup_killed_tool_counts_not_mistaken_for_never_ran(
    server, evidence_root, monkeypatch
):
    """SIGHUP surfaces as returncode -1, which must NOT be read as 'never ran'.

    This is the exact collision that a magic -1 sentinel would cause: a tool that
    RAN and was killed by SIGHUP (signal 1 -> returncode -1) would be mistaken for
    the never-ran sentinel and wrongly exempted. Keying never-ran on None (absence
    of a code), not on -1, makes exit_code -1 a genuine tool failure that counts.
    """

    def sighup(tool, args):
        return {
            "success": False,
            "stdout": "",
            "stderr": "Hangup",
            "exit_code": -1,  # killed by SIGHUP -- a REAL code, the tool ran
            "duration_ms": 5,
        }

    monkeypatch.setattr(server, "_execute", sighup)
    args = _args(evidence_root)
    for _ in range(3):
        server.run_tool("volatility", args, agent="memory_analyst", correlation_id="c")
    with pytest.raises(CircuitBreakerOpen):
        server.run_tool("volatility", args, agent="memory_analyst", correlation_id="c")


def test_never_ran_sentinel_is_none_and_is_exempt(server, evidence_root, monkeypatch):
    """The None sentinel (never ran) is exempt; no integer code is."""
    assert NEVER_RAN_EXIT_CODE is None

    def not_found(tool, args):
        return {
            "success": False,
            "stdout": "",
            "stderr": "Tool not found: volatility",
            "exit_code": NEVER_RAN_EXIT_CODE,  # None -> never ran
            "duration_ms": 1,
        }

    monkeypatch.setattr(server, "_execute", not_found)
    args = _args(evidence_root)
    for _ in range(6):
        server.run_tool("volatility", args, agent="memory_analyst", correlation_id="c")
    assert server.guard.failure_count == 0
