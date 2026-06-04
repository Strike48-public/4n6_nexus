# Agent-to-Agent (A2A) Message Log Schema

> Status: IMPLEMENTED. The `AgentMessage`, `FindingEmitted`, and `Verification`
> records, the `correlation_id`/`entry_id` envelope, and `AuditLogger.trace()` are
> implemented in `sift_find_evil/audit/` and exercised by the orchestration harness
> (`python -m sift_find_evil.orchestration`). This file remains the schema reference.
> Purpose: Satisfy FIND EVIL! Deliverable #8 (Agent Execution Logs, multi-agent variant) and
> the Audit Trail Quality criterion: "Judges must be able to trace any finding back to the
> specific tool execution that produced it." Designed to carry a FULL cross-domain
> verification round-trip (disk/timeline/memory/network) without future schema changes.

## Design principles

1. **Extend, don't replace.** Builds on the existing append-only JSONL `AuditLogger`
   (`sift_find_evil/audit/logger.py`) and `AuditEntry` model. One log stream, one ordering.
2. **One correlation thread per investigative thread.** A `correlation_id` is minted by the
   Orchestrator/Triage when a line of inquiry opens and is propagated through every downstream
   message, tool call, and finding. This thread IS the audit trail a judge follows.
3. **Findings are traceable by construction.** Every `Finding` carries the `correlation_id` and
   the `message_id` of the tool-result message that produced it. Reverse lookup is O(1).
4. **UTC, monotonic, append-only.** All timestamps ISO-8601 UTC with milliseconds. Entries are
   never mutated or deleted (anti-spoliation posture).

## Record types (single JSONL stream)

Every line is an `AuditEntry` with `action` ∈ the set below. Existing `tool_invocation` entries
are unchanged; we ADD agent-message entry types.

| `action` | Emitted when | Key payload |
|---|---|---|
| `agent_message` | One agent sends a message to another | sender, recipient, message_type, body |
| `tool_invocation` | An agent calls an MCP tool (EXISTING) | tool, command, exit_code, output_hash |
| `finding_emitted` | An analyst produces a candidate finding | finding_id, category, confidence, source_message_id |
| `verification` | Verifier challenges/confirms a finding | finding_id, verdict, contradiction_type, confidence_delta |
| `agent_lifecycle` | Agent spawned / completed / errored | agent, phase, status |

## Common envelope (all entries)

```json
{
  "schema_version": "a2a/1.0",
  "timestamp": "2026-06-04T14:25:03.412Z",
  "case_id": "INC-2026-001",
  "correlation_id": "corr-7f3a1c",
  "entry_id": "evt-000042",
  "action": "agent_message",
  "agent": "disk_analyst",
  "examiner": "jtomek",
  "details": { ... type-specific ... }
}
```

- `correlation_id`: stable across an investigative thread (e.g. "investigate malware.exe").
- `entry_id`: globally unique, monotonically increasing per log (`evt-NNNNNN`).
- `timestamp`: ISO-8601 UTC, millisecond precision.
- `agent`: the acting agent identity (DECIDED: per-agent identity). Enum: `orchestrator`,
  `triage`, `disk_analyst`, `memory_analyst`, `network_analyst`, `verifier`. Makes every
  entry self-documenting about which agent acted.
- `examiner`: the human examiner running the case (DECIDED: capture both agent + human for
  court-defensible chain of custody). Backward-compat note: existing `tool_invocation` callers
  that pass only `examiner` keep working; `agent` defaults to None for legacy entries.

## `agent_message` details

```json
{
  "sender": "triage",
  "recipient": "network_analyst",
  "message_type": "dispatch",
  "parent_message_id": "evt-000018",
  "body": {
    "task": "Analyze PCAP for exfiltration and beaconing",
    "artifacts": ["/evidence/capture.pcap"],
    "scope": ["exfil_ratio", "beaconing", "dns_anomaly"]
  }
}
```

`message_type` enum: `dispatch`, `result`, `challenge`, `response`, `escalation`, `handoff`.
`sender`/`recipient` enum: `orchestrator`, `triage`, `disk_analyst`, `memory_analyst`,
`network_analyst`, `verifier`.

## `finding_emitted` details

```json
{
  "finding_id": "F-003",
  "category": "timeline_tampering",
  "severity": "high",
  "confidence": 0.95,
  "produced_by": "disk_analyst",
  "source_message_id": "evt-000031",
  "source_tool_invocations": ["evt-000029", "evt-000030"],
  "artifact_refs": [
    {"type": "mft", "file": "malware.exe", "field": "si_modified", "value": "2026-..."}
  ]
}
```

`source_tool_invocations` is the explicit list of `tool_invocation` entry_ids whose output
produced this finding. THIS is the literal "trace any finding back to the specific tool
execution" link the rubric demands.

## `verification` details (the self-correction round-trip)

```json
{
  "finding_id": "F-003",
  "verifier": "verifier",
  "challenge_message_id": "evt-000035",
  "verdict": "contradiction_resolved",
  "contradiction_type": "causality_violation",
  "domain": "disk_timeline",
  "confidence_before": 0.95,
  "confidence_delta": -0.50,
  "recovery_delta": 0.30,
  "confidence_after": 0.75,
  "tiebreaker_tool_invocations": ["evt-000037"],
  "reasoning": "Prefetch run (14:25) precedes MFT mod (14:40); EventLog 4688 confirms 14:25 exec."
}
```

`verdict` enum: `confirmed`, `contradiction_detected`, `contradiction_resolved`,
`refuted`, `inconclusive`.
`domain` enum: `disk_timeline`, `exfil`, `memory`, `network` (latter two land in Phase B).

## Worked end-to-end trace (what a judge follows)

```
evt-000018 agent_message   orchestrator -> triage     dispatch  corr-7f3a1c
evt-000019 agent_message   triage -> disk_analyst      dispatch  corr-7f3a1c
evt-000029 tool_invocation disk_analyst  mftecmd ...             corr-7f3a1c
evt-000030 tool_invocation disk_analyst  pecmd ...               corr-7f3a1c
evt-000031 agent_message   disk_analyst -> orchestrator result   corr-7f3a1c
evt-000032 finding_emitted F-003 (conf 0.95, src evt-000029/30)  corr-7f3a1c
evt-000035 agent_message   orchestrator -> verifier    challenge corr-7f3a1c
evt-000037 tool_invocation verifier  evtxecmd 4688 ...           corr-7f3a1c
evt-000038 verification    F-003 resolved 0.95->0.75             corr-7f3a1c
evt-000040 agent_message   verifier -> orchestrator    response  corr-7f3a1c
```

A judge picks finding F-003, reads `source_tool_invocations` -> evt-000029/30, and reads the
`verification` entry -> sees the self-correction with its tiebreaker tool call. Full traceability,
single thread, timestamps throughout.

## Minimal implementation surface (Phase A)

- Add `AgentMessage`, `FindingEmitted`, `Verification` dataclasses to `audit/models.py`.
- Add `log_agent_message()`, `log_finding()`, `log_verification()` to `AuditLogger`.
- Add `entry_id` + `correlation_id` to the envelope (default-None for backward compat with
  existing `tool_invocation` callers so current tests keep passing).
- Add `AuditLogger.trace(finding_id)` helper that reconstructs the thread for the demo/report.

## Open questions for review
1. Is `claude-code` the right `examiner` value, or do we want per-agent examiner identity?
2. Should `correlation_id` be human-readable (e.g. "corr-malware-exe") for demo legibility, or
   opaque? (Recommendation: human-readable slug + short hash for demo clarity.)
3. Token-usage capture: rules want it for single-agent; for multi-agent it's optional. Capture
   per-`agent_message` anyway for a richer trace? (Low cost, nice-to-have.)
