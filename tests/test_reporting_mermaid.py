"""Tests for Mermaid diagram generation in investigation reports.

The report ships two GitHub-native Mermaid diagrams:
  - an A2A sequence diagram reconstructed from the audit log's agent_message
    entries (orchestrator -> triage -> analysts -> verifier),
  - a finding timeline / flow showing each finding and its verifier verdict.

Both are pure functions over data already in the audit log / report, so they are
tested in isolation. We assert the output is a well-formed ```mermaid``` fenced
block containing the expected diagram type and nodes — not exact whitespace.
"""

from __future__ import annotations

from sift_find_evil.reporting.mermaid import (
    mermaid_a2a_sequence,
    mermaid_finding_flow,
)


def _fenced(block: str) -> bool:
    """A valid embedded Mermaid block opens with ```mermaid and closes with ```."""
    s = block.strip()
    return s.startswith("```mermaid") and s.endswith("```")


# --- A2A sequence diagram ---------------------------------------------------

SAMPLE_A2A = [
    {
        "action": "agent_message",
        "agent": "orchestrator",
        "details": {
            "sender": "orchestrator",
            "recipient": "triage",
            "message_type": "dispatch",
        },
    },
    {
        "action": "agent_message",
        "agent": "triage",
        "details": {
            "sender": "triage",
            "recipient": "orchestrator",
            "message_type": "result",
        },
    },
    {
        "action": "tool_invocation",
        "agent": "disk_analyst",
        "details": {"tool": "mftecmd"},
    },
    {
        "action": "agent_message",
        "agent": "verifier",
        "details": {
            "sender": "verifier",
            "recipient": "orchestrator",
            "message_type": "result",
        },
    },
]


def test_a2a_sequence_is_fenced_mermaid_sequencediagram():
    out = mermaid_a2a_sequence(SAMPLE_A2A)
    assert _fenced(out)
    assert "sequenceDiagram" in out


def test_a2a_sequence_includes_participants_and_arrows():
    out = mermaid_a2a_sequence(SAMPLE_A2A)
    # Participants derived from senders/recipients.
    assert "orchestrator" in out
    assert "triage" in out
    assert "verifier" in out
    # At least one message arrow (Mermaid uses ->> for messages).
    assert "->>" in out


def test_a2a_sequence_ignores_non_agent_message_entries():
    # tool_invocation rows must not become sequence arrows.
    out = mermaid_a2a_sequence(SAMPLE_A2A)
    assert "mftecmd" not in out


def test_a2a_sequence_handles_empty_log():
    out = mermaid_a2a_sequence([])
    assert _fenced(out)
    assert "sequenceDiagram" in out  # still a valid (empty) diagram


# --- finding flow -----------------------------------------------------------

SAMPLE_FINDINGS = [
    {
        "finding_id": "F-001",
        "label": "ransom_note.exe",
        "domain": "disk_timeline",
        "verdict": "contradiction_resolved",
        "confidence_before": 0.95,
        "confidence_after": 0.75,
    },
    {
        "finding_id": "F-005",
        "label": "203.0.113.66",
        "domain": "network",
        "verdict": "contradiction_detected",
        "confidence_before": 0.9,
        "confidence_after": 0.45,
    },
]


def test_finding_flow_is_fenced_mermaid():
    out = mermaid_finding_flow(SAMPLE_FINDINGS)
    assert _fenced(out)
    assert "flowchart" in out or "graph" in out


def test_finding_flow_shows_each_finding_and_verdict():
    out = mermaid_finding_flow(SAMPLE_FINDINGS)
    assert "F-001" in out and "F-005" in out
    # The confidence transition is the story (0.95 -> 0.75, 0.9 -> 0.45).
    assert "0.95" in out and "0.75" in out
    assert "0.45" in out


def test_finding_flow_handles_empty():
    out = mermaid_finding_flow([])
    assert _fenced(out)


def test_mermaid_blocks_have_no_unescaped_breaking_chars():
    # Mermaid labels must not contain raw newlines or stray backticks that would
    # break the fenced block or the diagram parse.
    for out in (
        mermaid_a2a_sequence(SAMPLE_A2A),
        mermaid_finding_flow(SAMPLE_FINDINGS),
    ):
        body = out.strip().removeprefix("```mermaid").removesuffix("```")
        assert "```" not in body  # no nested fences


def test_finding_flow_truncates_long_labels():
    # A verbose finding title must not produce an unreadably wide node.
    long_title = "Partition table wiped " * 10  # ~220 chars
    out = mermaid_finding_flow(
        [
            {
                "finding_id": "F-001",
                "label": long_title,
                "verdict": "reported",
                "confidence": 0.95,
            }
        ]
    )
    # The label is truncated with an ellipsis marker; no single label line is huge.
    assert "..." in out
    longest_line = max((len(line) for line in out.splitlines()), default=0)
    assert longest_line < 120
