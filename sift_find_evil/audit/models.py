"""Data models for audit logging."""

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional


@dataclass
class ToolInvocation:
    """Record of a forensic tool invocation."""

    tool: str
    command: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    exit_code: Optional[int] = None
    duration_ms: Optional[int] = None
    output_hash: Optional[str] = None
    examiner: Optional[str] = None
    working_dir: Optional[str] = None
    stdout: Optional[str] = None
    stderr: Optional[str] = None

    def to_dict(self) -> dict:
        """Serialize to dictionary."""
        return {
            "timestamp": self.timestamp.isoformat(),
            "tool": self.tool,
            "command": self.command,
            "exit_code": self.exit_code,
            "duration_ms": self.duration_ms,
            "output_hash": self.output_hash,
            "examiner": self.examiner,
            "working_dir": self.working_dir,
            "stdout": self.stdout,
            "stderr": self.stderr,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "ToolInvocation":
        """Deserialize from dictionary."""
        return cls(
            tool=data["tool"],
            command=data["command"],
            timestamp=datetime.fromisoformat(data["timestamp"]),
            exit_code=data.get("exit_code"),
            duration_ms=data.get("duration_ms"),
            output_hash=data.get("output_hash"),
            examiner=data.get("examiner"),
            working_dir=data.get("working_dir"),
            stdout=data.get("stdout"),
            stderr=data.get("stderr"),
        )


# Genesis anchor for the audit hash chain. The first real entry commits to this
# constant so an attacker cannot silently drop the head of the log: a chain that
# does not begin at GENESIS is detectably truncated.
GENESIS_HASH = "0" * 64


def compute_entry_hash(body_without_hash: dict) -> str:
    """Compute the full SHA-256 chain digest over an entry body.

    The body must already include ``prev_hash`` (so the digest commits to the
    prior entry) and must EXCLUDE ``entry_hash`` itself (a hash cannot commit to
    its own value). Canonicalization matches the approval-signing convention
    (sort_keys + tight separators + ``default=str``) so the byte sequence is
    reproducible across processes and Python versions.
    """
    canonical = json.dumps(
        body_without_hash, sort_keys=True, separators=(",", ":"), default=str
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclass
class AuditEntry:
    """Base audit entry for any logged action.

    Extended for the multi-agent (A2A) log per analysis/A2A_MESSAGE_SCHEMA.md:
    ``entry_id`` and ``correlation_id`` thread an investigative line of inquiry,
    and ``agent`` records the acting agent identity (distinct from the human
    ``examiner``). All four are optional so legacy/tool-only callers are unaffected.

    Tamper-evidence (gallery idea #1): ``prev_hash`` links each entry to the
    digest of the prior entry and ``entry_hash`` is the SHA-256 over this entry's
    canonical body (with ``prev_hash`` included, ``entry_hash`` excluded). Both
    are assigned by ``AuditLogger`` at write time; they are optional on the
    dataclass so legacy readers and hand-built entries still deserialize.
    """

    action: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    examiner: Optional[str] = None
    details: Optional[dict] = None
    entry_id: Optional[str] = None
    correlation_id: Optional[str] = None
    agent: Optional[str] = None
    prev_hash: Optional[str] = None
    entry_hash: Optional[str] = None

    def to_dict(self) -> dict:
        """Serialize to dictionary.

        ``prev_hash``/``entry_hash`` are emitted only once assigned so the
        serialized shape of legacy (unchained) entries is byte-identical to
        before; the chain fields are additive.
        """
        data = {
            "timestamp": self.timestamp.isoformat(),
            "action": self.action,
            "agent": self.agent,
            "examiner": self.examiner,
            "correlation_id": self.correlation_id,
            "entry_id": self.entry_id,
            "details": self.details,
        }
        if self.prev_hash is not None:
            data["prev_hash"] = self.prev_hash
        if self.entry_hash is not None:
            data["entry_hash"] = self.entry_hash
        return data

    def chain_body(self) -> dict:
        """Return the canonical body the ``entry_hash`` is computed over.

        Includes ``prev_hash`` (the entry commits to its predecessor) and
        excludes ``entry_hash`` (a digest cannot commit to itself).
        """
        return {k: v for k, v in self.to_dict().items() if k != "entry_hash"}

    @classmethod
    def from_dict(cls, data: dict) -> "AuditEntry":
        """Deserialize from dictionary (tolerant of legacy entries)."""
        return cls(
            action=data["action"],
            timestamp=datetime.fromisoformat(data["timestamp"]),
            examiner=data.get("examiner"),
            details=data.get("details"),
            entry_id=data.get("entry_id"),
            correlation_id=data.get("correlation_id"),
            agent=data.get("agent"),
            prev_hash=data.get("prev_hash"),
            entry_hash=data.get("entry_hash"),
        )


@dataclass
class AgentMessage:
    """A message sent from one agent to another (A2A log).

    Satisfies FIND EVIL! deliverable #8 (multi-agent variant): agent-to-agent
    message logs with timestamps.
    """

    sender: str
    recipient: str
    message_type: str  # dispatch | result | challenge | response | escalation | handoff
    body: dict
    parent_message_id: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "sender": self.sender,
            "recipient": self.recipient,
            "message_type": self.message_type,
            "parent_message_id": self.parent_message_id,
            "body": self.body,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "AgentMessage":
        return cls(
            sender=data["sender"],
            recipient=data["recipient"],
            message_type=data["message_type"],
            body=data.get("body", {}),
            parent_message_id=data.get("parent_message_id"),
        )


@dataclass
class FindingEmitted:
    """A candidate finding emitted by an analyst agent.

    ``source_tool_invocations`` is the explicit list of tool-invocation entry_ids
    whose output produced this finding -- the literal "trace any finding back to
    the specific tool execution" link the Audit Trail Quality criterion demands.
    """

    finding_id: str
    category: str
    severity: str
    confidence: float
    produced_by: str
    source_tool_invocations: list[str] = field(default_factory=list)
    source_message_id: Optional[str] = None
    artifact_refs: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "finding_id": self.finding_id,
            "category": self.category,
            "severity": self.severity,
            "confidence": self.confidence,
            "produced_by": self.produced_by,
            "source_message_id": self.source_message_id,
            "source_tool_invocations": self.source_tool_invocations,
            "artifact_refs": self.artifact_refs,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "FindingEmitted":
        return cls(
            finding_id=data["finding_id"],
            category=data["category"],
            severity=data["severity"],
            confidence=data["confidence"],
            produced_by=data["produced_by"],
            source_tool_invocations=data.get("source_tool_invocations", []),
            source_message_id=data.get("source_message_id"),
            artifact_refs=data.get("artifact_refs", []),
        )


@dataclass
class Verification:
    """A verifier agent's challenge/confirmation of a finding (self-correction)."""

    finding_id: str
    verifier: str
    verdict: str  # confirmed | contradiction_detected | contradiction_resolved | refuted | inconclusive
    domain: str  # disk_timeline | exfil | memory | network
    confidence_before: float
    confidence_after: float
    contradiction_type: Optional[str] = None
    confidence_delta: float = 0.0
    recovery_delta: float = 0.0
    tiebreaker_tool_invocations: list[str] = field(default_factory=list)
    challenge_message_id: Optional[str] = None
    reasoning: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "finding_id": self.finding_id,
            "verifier": self.verifier,
            "verdict": self.verdict,
            "domain": self.domain,
            "contradiction_type": self.contradiction_type,
            "confidence_before": self.confidence_before,
            "confidence_delta": self.confidence_delta,
            "recovery_delta": self.recovery_delta,
            "confidence_after": self.confidence_after,
            "tiebreaker_tool_invocations": self.tiebreaker_tool_invocations,
            "challenge_message_id": self.challenge_message_id,
            "reasoning": self.reasoning,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Verification":
        return cls(
            finding_id=data["finding_id"],
            verifier=data["verifier"],
            verdict=data["verdict"],
            domain=data["domain"],
            confidence_before=data["confidence_before"],
            confidence_after=data["confidence_after"],
            contradiction_type=data.get("contradiction_type"),
            confidence_delta=data.get("confidence_delta", 0.0),
            recovery_delta=data.get("recovery_delta", 0.0),
            tiebreaker_tool_invocations=data.get("tiebreaker_tool_invocations", []),
            challenge_message_id=data.get("challenge_message_id"),
            reasoning=data.get("reasoning"),
        )


def calculate_output_hash(output: str) -> str:
    """Calculate SHA-256 hash of tool output."""
    return hashlib.sha256(output.encode("utf-8")).hexdigest()[:16]
