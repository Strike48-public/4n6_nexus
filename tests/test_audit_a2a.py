"""Tests for the A2A (agent-to-agent) audit log extension.

Implements analysis/A2A_MESSAGE_SCHEMA.md. Validates:
- AgentMessage / FindingEmitted / Verification dataclasses round-trip
- AuditLogger.log_agent_message / log_finding / log_verification
- Envelope carries entry_id + correlation_id + agent + examiner
- Backward compatibility: existing tool_invocation entries keep working
- AuditLogger.trace(finding_id) reconstructs the full investigative thread

FIND EVIL! deliverable #8 (multi-agent execution logs) + Audit Trail Quality:
"Judges must be able to trace any finding back to the specific tool execution."
"""

from __future__ import annotations

import json

import pytest

from sift_find_evil.audit.logger import AuditLogger
from sift_find_evil.audit.models import (
    AgentMessage,
    FindingEmitted,
    Verification,
)


@pytest.fixture
def audit_path(tmp_path):
    return tmp_path / "audit.jsonl"


@pytest.fixture
def logger(audit_path):
    return AuditLogger(audit_path, examiner="jtomek")


# --------------------------------------------------------------------------
# Dataclass round-trips
# --------------------------------------------------------------------------


def test_agent_message_round_trips_through_dict():
    msg = AgentMessage(
        sender="triage",
        recipient="network_analyst",
        message_type="dispatch",
        body={"task": "Analyze PCAP", "artifacts": ["/evidence/capture.pcap"]},
        parent_message_id="evt-000018",
    )

    restored = AgentMessage.from_dict(msg.to_dict())

    assert restored.sender == "triage"
    assert restored.recipient == "network_analyst"
    assert restored.message_type == "dispatch"
    assert restored.body["task"] == "Analyze PCAP"
    assert restored.parent_message_id == "evt-000018"


def test_finding_emitted_links_to_source_tool_invocations():
    finding = FindingEmitted(
        finding_id="F-003",
        category="timeline_tampering",
        severity="high",
        confidence=0.95,
        produced_by="disk_analyst",
        source_message_id="evt-000031",
        source_tool_invocations=["evt-000029", "evt-000030"],
        artifact_refs=[{"type": "mft", "file": "malware.exe"}],
    )

    restored = FindingEmitted.from_dict(finding.to_dict())

    assert restored.finding_id == "F-003"
    assert restored.source_tool_invocations == ["evt-000029", "evt-000030"]
    assert restored.confidence == 0.95


def test_verification_records_self_correction_round_trip():
    v = Verification(
        finding_id="F-003",
        verifier="verifier",
        verdict="contradiction_resolved",
        contradiction_type="causality_violation",
        domain="disk_timeline",
        confidence_before=0.95,
        confidence_delta=-0.50,
        recovery_delta=0.30,
        confidence_after=0.75,
        tiebreaker_tool_invocations=["evt-000037"],
        reasoning="Prefetch run precedes MFT mod; EventLog 4688 confirms exec.",
    )

    restored = Verification.from_dict(v.to_dict())

    assert restored.verdict == "contradiction_resolved"
    assert restored.confidence_after == 0.75
    assert restored.tiebreaker_tool_invocations == ["evt-000037"]


# --------------------------------------------------------------------------
# Envelope: entry_id, correlation_id, agent, examiner
# --------------------------------------------------------------------------


def test_log_agent_message_writes_envelope_with_identity(logger, audit_path):
    logger.log_agent_message(
        AgentMessage(
            sender="orchestrator",
            recipient="triage",
            message_type="dispatch",
            body={"task": "open case"},
        ),
        correlation_id="corr-malware-exe",
        agent="orchestrator",
    )

    lines = audit_path.read_text().strip().splitlines()
    assert len(lines) == 1
    rec = json.loads(lines[0])

    assert rec["action"] == "agent_message"
    assert rec["agent"] == "orchestrator"  # acting agent identity
    assert rec["examiner"] == "jtomek"  # human examiner
    assert rec["correlation_id"] == "corr-malware-exe"
    assert rec["entry_id"].startswith("evt-")  # auto-assigned
    assert rec["timestamp"].endswith(("Z", "+00:00")) or "T" in rec["timestamp"]
    assert rec["details"]["sender"] == "orchestrator"
    assert rec["details"]["recipient"] == "triage"


def test_entry_ids_are_monotonic_and_unique(logger):
    for i in range(3):
        logger.log_agent_message(
            AgentMessage(
                sender="triage",
                recipient="disk_analyst",
                message_type="dispatch",
                body={"n": i},
            ),
            correlation_id="corr-x",
            agent="triage",
        )

    entries = logger.get_recent(limit=10)
    ids = [e.entry_id for e in entries]
    assert len(set(ids)) == 3  # unique
    # monotonic regardless of recency ordering
    nums = sorted(int(i.split("-")[1]) for i in ids)
    assert nums == list(range(nums[0], nums[0] + 3))


# --------------------------------------------------------------------------
# Backward compatibility
# --------------------------------------------------------------------------


def test_existing_tool_invocation_logging_still_works(logger, audit_path):
    # The pre-existing API must keep functioning with no A2A fields required.
    logger.log_tool_invocation(
        tool="mftecmd",
        command="mftecmd -f $MFT --csv out",
        exit_code=0,
        duration_ms=120,
        output="parsed 1000 entries",
    )

    rec = json.loads(audit_path.read_text().strip())
    assert rec["action"] == "tool_invocation"
    assert rec["details"]["tool"] == "mftecmd"
    # legacy entries simply have no acting-agent identity
    assert rec.get("agent") is None


def test_legacy_entry_without_entry_id_deserializes(audit_path):
    # Simulate a log written by the OLD schema (no entry_id/correlation_id/agent).
    legacy = {
        "timestamp": "2026-06-04T14:25:03",
        "action": "tool_invocation",
        "examiner": "jtomek",
        "details": {"tool": "vol.py", "command": "vol.py -f mem windows.pslist"},
    }
    audit_path.write_text(json.dumps(legacy) + "\n")

    logger = AuditLogger(audit_path, examiner="jtomek")
    entries = logger.get_recent(limit=5)
    assert len(entries) == 1
    assert entries[0].action == "tool_invocation"
    assert entries[0].entry_id is None or entries[0].entry_id.startswith("evt-")


def test_new_entry_ids_continue_after_existing_log(audit_path):
    # Seed two existing A2A entries, reopen, ensure new ids do not collide.
    logger1 = AuditLogger(audit_path, examiner="jtomek")
    logger1.log_agent_message(
        AgentMessage(
            sender="orchestrator", recipient="triage", message_type="dispatch", body={}
        ),
        correlation_id="corr-x",
        agent="orchestrator",
    )
    logger2 = AuditLogger(audit_path, examiner="jtomek")
    logger2.log_agent_message(
        AgentMessage(
            sender="triage", recipient="disk_analyst", message_type="dispatch", body={}
        ),
        correlation_id="corr-x",
        agent="triage",
    )

    ids = [
        json.loads(line)["entry_id"]
        for line in audit_path.read_text().strip().splitlines()
    ]
    assert len(set(ids)) == 2  # no collision across logger instances


# --------------------------------------------------------------------------
# Traceability: the Audit Trail Quality criterion
# --------------------------------------------------------------------------


def test_trace_reconstructs_full_thread_for_a_finding(logger):
    corr = "corr-malware-exe"

    # 1. orchestrator -> triage -> disk_analyst dispatch
    logger.log_agent_message(
        AgentMessage(
            sender="orchestrator", recipient="triage", message_type="dispatch", body={}
        ),
        correlation_id=corr,
        agent="orchestrator",
    )
    logger.log_agent_message(
        AgentMessage(
            sender="triage", recipient="disk_analyst", message_type="dispatch", body={}
        ),
        correlation_id=corr,
        agent="triage",
    )

    # 2. disk_analyst runs two tools
    tool1 = logger.log_tool_invocation(
        tool="mftecmd",
        command="mftecmd -f $MFT --csv out",
        exit_code=0,
        correlation_id=corr,
        agent="disk_analyst",
    )
    tool2 = logger.log_tool_invocation(
        tool="pecmd",
        command="pecmd -d Prefetch --csv out",
        exit_code=0,
        correlation_id=corr,
        agent="disk_analyst",
    )

    # 3. finding emitted, linked to the two tool invocations
    logger.log_finding(
        FindingEmitted(
            finding_id="F-003",
            category="timeline_tampering",
            severity="high",
            confidence=0.95,
            produced_by="disk_analyst",
            source_message_id=None,
            source_tool_invocations=[tool1, tool2],
            artifact_refs=[{"type": "mft", "file": "malware.exe"}],
        ),
        correlation_id=corr,
        agent="disk_analyst",
    )

    # 4. verifier challenge -> tiebreaker tool -> verification
    tiebreaker = logger.log_tool_invocation(
        tool="evtxecmd",
        command="evtxecmd -f Security.evtx --csv out",
        exit_code=0,
        correlation_id=corr,
        agent="verifier",
    )
    logger.log_verification(
        Verification(
            finding_id="F-003",
            verifier="verifier",
            verdict="contradiction_resolved",
            contradiction_type="causality_violation",
            domain="disk_timeline",
            confidence_before=0.95,
            confidence_delta=-0.50,
            recovery_delta=0.30,
            confidence_after=0.75,
            tiebreaker_tool_invocations=[tiebreaker],
            reasoning="EventLog 4688 confirms exec time.",
        ),
        correlation_id=corr,
        agent="verifier",
    )

    thread = logger.trace("F-003")

    # The trace must surface the finding, its source tools, and the verification
    actions = [e.action for e in thread]
    assert "finding_emitted" in actions
    assert "verification" in actions
    assert "tool_invocation" in actions

    # Every entry in the trace shares the correlation thread
    assert all(e.correlation_id == corr for e in thread)

    # The specific tool executions that produced the finding are reachable
    entry_ids = {e.entry_id for e in thread}
    assert tool1 in entry_ids
    assert tool2 in entry_ids
    assert tiebreaker in entry_ids


def test_log_tool_invocation_returns_entry_id(logger):
    entry_id = logger.log_tool_invocation(
        tool="vol.py",
        command="vol.py -f mem windows.pslist",
        exit_code=0,
        correlation_id="corr-x",
        agent="memory_analyst",
    )
    assert entry_id.startswith("evt-")


def test_trace_unknown_finding_returns_empty(logger):
    assert logger.trace("F-does-not-exist") == []
