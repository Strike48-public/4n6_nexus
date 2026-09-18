"""Tests for the Custom MCP server boundary integration.

Verifies that the server's tool dispatch routes every invocation through the
architectural guardrails AND records it in the A2A audit log -- so the MCP
boundary IS the audit trail. Transport (stdio) is not exercised here; we test
the dispatch core that the FastMCP handlers delegate to.
"""

from __future__ import annotations

import pytest

from sift_find_evil.mcp.guardrails import GuardrailViolation
from sift_find_evil.mcp.jobs import NEVER_RAN_EXIT_CODE
from sift_find_evil.mcp.server import EvidenceMCPServer


@pytest.fixture
def evidence_root(tmp_path):
    root = tmp_path / "evidence"
    root.mkdir()
    (root / "memory.raw").write_bytes(b"fake mem")
    return root


@pytest.fixture
def server(tmp_path, evidence_root):
    return EvidenceMCPServer(
        case_id="INC-2026-001",
        evidence_root=evidence_root,
        audit_path=tmp_path / "audit.jsonl",
        examiner="jdoe",
    )


def test_blocked_invocation_is_denied_and_audited(server, evidence_root):
    # An agent attempts to read outside the evidence root.
    with pytest.raises(GuardrailViolation):
        server.run_tool(
            tool="volatility",
            args=["-f", "/etc/shadow", "-r", "json", "windows.pslist"],
            agent="memory_analyst",
            correlation_id="corr-x",
        )

    # The blocked attempt must still be recorded for the audit trail.
    entries = server.audit_logger.get_recent(limit=10)
    actions = [e.action for e in entries]
    assert any(a in ("tool_blocked", "tool_invocation") for a in actions)
    blocked = [e for e in entries if e.action == "tool_blocked"]
    assert blocked, "a guardrail denial must be logged as tool_blocked"
    assert blocked[0].agent == "memory_analyst"
    assert blocked[0].correlation_id == "corr-x"


def test_unknown_tool_is_denied(server):
    with pytest.raises(GuardrailViolation):
        server.run_tool(
            tool="rm",
            args=["-rf", "/"],
            agent="disk_analyst",
            correlation_id="corr-x",
        )


def test_allowed_invocation_returns_entry_id_for_tracing(
    server, evidence_root, monkeypatch
):
    # Stub actual subprocess execution; we are testing the boundary, not Volatility.
    def fake_exec(tool, args):
        return {
            "success": True,
            "stdout": "[]",
            "stderr": "",
            "exit_code": 0,
            "duration_ms": 5,
        }

    monkeypatch.setattr(server, "_execute", fake_exec)

    result = server.run_tool(
        tool="volatility",
        args=["-f", str(evidence_root / "memory.raw"), "-r", "json", "windows.pslist"],
        agent="memory_analyst",
        correlation_id="corr-x",
    )

    assert result["success"] is True
    # The invocation must yield a traceable audit entry_id.
    assert result["entry_id"].startswith("evt-")
    entries = server.audit_logger.get_recent(limit=10)
    assert any(
        e.action == "tool_invocation" and e.agent == "memory_analyst" for e in entries
    )


def test_failure_trips_circuit_breaker_after_threshold(
    server, evidence_root, monkeypatch
):
    def failing_exec(tool, args):
        return {
            "success": False,
            "stdout": "",
            "stderr": "boom",
            "exit_code": 1,
            "duration_ms": 5,
        }

    monkeypatch.setattr(server, "_execute", failing_exec)
    args = ["-f", str(evidence_root / "memory.raw"), "-r", "json", "windows.pslist"]

    # 3 failures open the breaker; the 4th call is refused by the guardrail.
    for _ in range(3):
        server.run_tool(
            tool="volatility",
            args=args,
            agent="memory_analyst",
            correlation_id="corr-x",
        )

    from sift_find_evil.mcp.guardrails import CircuitBreakerOpen

    with pytest.raises(CircuitBreakerOpen):
        server.run_tool(
            tool="volatility",
            args=args,
            agent="memory_analyst",
            correlation_id="corr-x",
        )


def test_default_policies_cover_core_forensic_tools(server):
    # The server ships sane read-only policies for the bundled tool wrappers.
    assert set(server.guard.policies).issuperset(
        {"volatility", "mftecmd", "pecmd", "evtxecmd", "tshark"}
    )


def test_added_tool_inherits_readonly_guardrail(server, evidence_root, monkeypatch):
    """A newly added tool (tshark) gets read-only enforcement for free.

    This is the extension-path contract: registering a tool at the MCP boundary
    means it inherits the allowlist. tshark's write flag (-w, save a capture) is
    not on its allowlist, so it is rejected by construction -- no extra code.
    """

    def fake_exec(tool, args):
        return {
            "success": True,
            "stdout": "",
            "stderr": "",
            "exit_code": 0,
            "duration_ms": 1,
        }

    monkeypatch.setattr(server, "_execute", fake_exec)
    pcap = evidence_root / "capture.pcap"
    pcap.write_bytes(b"fake pcap")

    # Read-only field extraction inside the evidence root is allowed.
    ok = server.run_tool(
        tool="tshark",
        args=["-r", str(pcap), "-T", "fields", "-e", "ip.src"],
        agent="network_analyst",
        correlation_id="corr-x",
    )
    assert ok["success"] is True

    # Attempting to WRITE a capture (-w) is rejected: not on the allowlist.
    with pytest.raises(GuardrailViolation):
        server.run_tool(
            tool="tshark",
            args=["-r", str(pcap), "-w", "/tmp/exfil.pcap"],
            agent="network_analyst",
            correlation_id="corr-x",
        )


# --- SEC-1 (SFE-eol): blocked-call auditing must stay append-only -----------


def test_blocked_call_audit_is_append_only(server, tmp_path):
    """A blocked call must be recorded by APPENDING, never by rewriting the log.

    Regression guard for SFE-eol: the old _stamp_last_entry read the whole log
    and wrote it back, breaking the append-only / tamper-evident guarantee. The
    file's existing bytes must be untouched -- only new bytes appended.
    """
    audit_path = server.audit_logger.audit_path

    # Seed a prior entry so there is existing content that must be preserved.
    server.audit_logger.log_action("session_start", details={"case": "INC-2026-001"})
    before = audit_path.read_bytes()

    with pytest.raises(GuardrailViolation):
        server.run_tool(
            tool="volatility",
            args=["-f", "/etc/shadow", "-r", "json", "windows.pslist"],
            agent="memory_analyst",
            correlation_id="corr-append",
        )

    after = audit_path.read_bytes()
    # Append-only: the prior bytes are an unchanged prefix; the log only grew.
    assert after.startswith(before), "existing audit bytes were rewritten"
    assert len(after) > len(before), "blocked call was not appended"

    # And the blocked entry still carries its A2A identity (no _stamp rewrite).
    blocked = [
        e
        for e in server.audit_logger.get_recent(limit=10)
        if e.action == "tool_blocked"
    ]
    assert blocked and blocked[0].agent == "memory_analyst"
    assert blocked[0].correlation_id == "corr-append"


def test_concurrent_blocked_calls_lose_no_entries(server):
    """Concurrent blocked calls must not drop audit entries (TOCTOU guard).

    The old read-modify-write _stamp_last_entry raced: a write landing between
    read_text() and write_text() was silently lost. With append-only logging,
    every blocked attempt survives.
    """
    import threading

    threads_n, per_thread = 8, 10

    def hammer(tid: int) -> None:
        for _ in range(per_thread):
            try:
                server.run_tool(
                    tool="volatility",
                    args=["-f", "/etc/shadow", "-r", "json", "windows.pslist"],
                    agent=f"agent-{tid}",
                    correlation_id=f"corr-{tid}",
                )
            except GuardrailViolation:
                pass

    threads = [threading.Thread(target=hammer, args=(i,)) for i in range(threads_n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    entries = server.audit_logger._read_all()
    blocked = [e for e in entries if e.action == "tool_blocked"]
    assert (
        len(blocked) == threads_n * per_thread
    ), f"expected {threads_n * per_thread} blocked entries, got {len(blocked)}"


def test_volatility_key_execs_vol_binary(server, evidence_root, monkeypatch):
    """SFE-wnr4: the ``volatility`` tool key must spawn the real ``vol`` binary.

    Volatility 3 installs its CLI as ``vol``; keying the guardrail/audit as
    ``volatility`` while execing the literal ``volatility`` would fail with
    tool-not-found on every tier. ``_execute`` translates the key at the exec
    boundary, so the spawned argv[0] must be ``vol`` even though the audit and
    the run_tool call use ``volatility``.
    """
    import subprocess as _subprocess

    captured = {}

    def fake_run(argv, **kwargs):
        captured["argv"] = argv

        class _Proc:
            returncode = 0
            stdout = "[]"
            stderr = ""

        return _Proc()

    monkeypatch.setattr(_subprocess, "run", fake_run)

    result = server.run_tool(
        tool="volatility",
        args=["-f", str(evidence_root / "memory.raw"), "-r", "json", "windows.pslist"],
        agent="memory_analyst",
        correlation_id="corr-vol",
    )

    assert result["success"] is True
    # Exec boundary spawned the real binary...
    assert captured["argv"][0] == "vol"
    # ...but the audit trail keeps the logical tool key.
    entries = server.audit_logger._read_all()
    invs = [e for e in entries if e.action == "tool_invocation"]
    assert invs and invs[-1].details["tool"] == "volatility"


def test_identity_tool_key_execs_same_binary(server, evidence_root, monkeypatch):
    """A tool whose key == its binary (mftecmd) must exec unchanged."""
    import subprocess as _subprocess

    captured = {}

    def fake_run(argv, **kwargs):
        captured["argv"] = argv

        class _Proc:
            returncode = 0
            stdout = ""
            stderr = ""

        return _Proc()

    monkeypatch.setattr(_subprocess, "run", fake_run)
    (evidence_root / "MFT").write_bytes(b"\x00")
    (evidence_root / "out").mkdir()

    server.run_tool(
        tool="mftecmd",
        args=[
            "-f",
            str(evidence_root / "MFT"),
            "--csv",
            str(evidence_root.parent / "out"),
        ],
        agent="disk_analyst",
        correlation_id="corr-mft",
    )
    assert captured["argv"][0] == "mftecmd"


# -- platform-gated tools at the exec doorway (SFE-ybki) ---------------------


def test_execute_refuses_platform_unsupported_tool_instead_of_hollow_success(
    server, monkeypatch
):
    """PECmd on Linux exits 0 without working, so returncode alone lies.

    The advertise gate stops the connector OFFERING pecmd here, but a caller can
    name a tool directly (Matrix Mode A routes on the request's tool key), so the
    exec boundary must refuse too rather than score the no-op a success.
    """
    monkeypatch.setattr("sift_find_evil.mcp.server.platform.system", lambda: "Linux")

    def _must_not_spawn(*_a, **_k):  # pragma: no cover - asserts non-invocation
        raise AssertionError("subprocess.run must not be reached for a gated tool")

    monkeypatch.setattr("sift_find_evil.mcp.server.subprocess.run", _must_not_spawn)

    result = server._execute("pecmd", ["-d", "/eviden/prefetch"])

    assert result["success"] is False
    # NEVER_RAN (None), not 0 and not a tool failure: the tool never ran, so the
    # circuit breaker must not be penalised for an environment condition.
    assert result["exit_code"] is NEVER_RAN_EXIT_CODE
    assert "platform" in result["stderr"].lower()
    assert "pecmd" in result["stderr"]


def test_execute_still_runs_cross_platform_tool_on_linux(server, monkeypatch):
    # Scope guard: the gate must not block the tools that DO work on Linux.
    monkeypatch.setattr("sift_find_evil.mcp.server.platform.system", lambda: "Linux")
    spawned = {}

    class _Proc:
        returncode = 0
        stdout = "ok"
        stderr = ""

    def _fake_run(cmd, **_k):
        spawned["cmd"] = cmd
        return _Proc()

    monkeypatch.setattr("sift_find_evil.mcp.server.subprocess.run", _fake_run)

    result = server._execute("mftecmd", ["-f", "/evidence/$MFT"])

    assert result["success"] is True
    assert spawned["cmd"][0] == "mftecmd"


def test_execute_runs_pecmd_on_windows(server, monkeypatch):
    # The gate is conditional, not a deletion: PECmd works on Windows.
    monkeypatch.setattr("sift_find_evil.mcp.server.platform.system", lambda: "Windows")

    class _Proc:
        returncode = 0
        stdout = "ok"
        stderr = ""

    monkeypatch.setattr(
        "sift_find_evil.mcp.server.subprocess.run", lambda cmd, **_k: _Proc()
    )

    assert server._execute("pecmd", ["-d", "C:\\prefetch"])["success"] is True
