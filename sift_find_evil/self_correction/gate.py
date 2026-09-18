"""Report-blocking gate: compose the adversarial verdict into a gate (SFE-fibx.5 PR-D).

The adversarial verifier already runs on the shipping harden path and records a
per-finding outcome (sustained / dismissed / remanded), but nothing acts on it.
This module composes those outcomes -- plus the kill-chain-coherence protection
(PR-A) and the coverage audit (PR-B) -- into a single gate verdict the emitters
enforce. The gate DEGRADES rather than refuses: the report is always written,
stamped with the verdict + reasons, and the CLI exits non-zero on a non-PASS so
automation treats it as a hard gate.

Calibration matters here. Measured across the 16 scored scenarios, findings are
overwhelmingly single-source ``remanded`` (survived the falsifier but lack a
second corroborating source), with a few ``sustained`` and ZERO ``dismissed``.
So ``remanded`` is the NORMAL case for a narrow scenario and must NOT trip the
gate -- gating on it would flag ~90% of every clean run. The gate blocks on a
genuinely bad state: a ``dismissed`` finding is one whose asserted identity
anchor (an IP/PID) could not be re-derived from the evidence -- a hallucinated
value -- and shipping that is the integrity failure the gate exists to stop.

The kill-chain rule: a ``dismissed`` finding that is a member of a
coherent 3+-phase chain (grouped per investigative subject) is corroborated by
that chain, so it is "harder to dismiss" -- the gate escalates it to human review
rather than blocking outright (the chain vouches for it; a human should decide).
A ``dismissed`` finding that is NOT chain-protected stays blocked.

Pure and deterministic: never mutates its inputs, produces no side effects.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from ..findings.dedup import canonical_entity
from .kill_chain import assess_chain, is_protected

# Gate verdicts, in ascending severity. Precedence when several apply:
# BLOCKED > NEEDS_HUMAN > PASS.
PASS = "PASS"
NEEDS_HUMAN = "NEEDS_HUMAN"
BLOCKED = "BLOCKED"

_SEVERITY = {PASS: 0, NEEDS_HUMAN: 1, BLOCKED: 2}


@dataclass(frozen=True)
class GateVerdict:
    """The composed gate ruling for one hardened finding set.

    Attributes:
        verdict: PASS / NEEDS_HUMAN / BLOCKED, driven ONLY by finding-level
            causes (a dismissed finding). This is what the emitter turns into a
            non-zero exit -- a real integrity problem, not a partial-evidence run.
        reasons: Human-readable lines for the finding-level causes behind the
            verdict, one per triggering finding.
        blocked_findings: Titles of the findings that caused a BLOCK (empty
            unless verdict is BLOCKED).
        advisories: Non-blocking flags (e.g. coverage gaps: important artifact
            classes not examined). Stamped on the report so the investigator sees
            them, but they NEVER change the verdict or force a non-zero exit --
            "flag, not block", because a deliberately-partial analysis is normal
            and gating every one of them is alarm fatigue.
    """

    verdict: str
    reasons: tuple[str, ...] = field(default_factory=tuple)
    blocked_findings: tuple[str, ...] = field(default_factory=tuple)
    advisories: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation."""
        return {
            "verdict": self.verdict,
            "reasons": list(self.reasons),
            "blocked_findings": list(self.blocked_findings),
            "advisories": list(self.advisories),
        }


def _entity_key(finding: dict) -> Any:
    """A stable grouping key for one finding's investigative subject.

    Uses the canonical entity (PR-A caller contract: group by subject before
    assessing a chain). A finding with no structured entity groups under a unique
    sentinel so it never accidentally shares a chain with another subject.
    """
    ent = canonical_entity(finding)
    if ent is not None:
        return (ent.kind, ent.value)
    # No canonical entity -> its own singleton group (id() is stable within a run
    # and never collides with a real (kind, value) tuple).
    return ("_none", id(finding))


def build_gate(
    hardened: list[dict],
    coverage: dict[str, Any],
    negatives: list[dict],
) -> GateVerdict:
    """Compose the adversarial outcomes + kill-chain + coverage into a verdict.

    Args:
        hardened: The ``HardeningReport.hardened`` entries (each carries a
            ``finding`` dict and an ``adversarial`` ruling dict). Not mutated.
        coverage: The ``HardeningReport.coverage`` dict (PR-B); its
            ``not_examined`` list drives a NEEDS_HUMAN advisory.
        negatives: The proven-negative findings (PR-C). Accepted for a complete
            gate input; they are corroborating context, never a block cause.

    Returns:
        A GateVerdict. PASS unless a dismissed finding blocks (or escalates via
        chain protection) or an important artifact class was not examined.
    """
    # Group findings by investigative subject, then assess each group's chain
    # coherence once (PR-A: coherence is per-subject, not across the whole set).
    groups: dict[Any, list[dict]] = defaultdict(list)
    for entry in hardened:
        groups[_entity_key(entry.get("finding", {}))].append(entry)

    protected_ids: set[int] = set()
    for members in groups.values():
        findings = [m.get("finding", {}) for m in members]
        assessment = assess_chain(findings)
        if not assessment.is_coherent:
            continue
        for m in members:
            if is_protected(m.get("finding", {}), assessment):
                protected_ids.add(id(m))

    reasons: list[str] = []
    blocked: list[str] = []
    verdict = PASS

    def _raise_to(level: str) -> None:
        nonlocal verdict
        if _SEVERITY[level] > _SEVERITY[verdict]:
            verdict = level

    for entry in hardened:
        outcome = (entry.get("adversarial") or {}).get("outcome")
        if outcome != "dismissed":
            # sustained / remanded / anything else is gate-clean: remanded is the
            # expected single-source case, not a failure.
            continue
        title = str((entry.get("finding") or {}).get("title", "<finding>"))
        if id(entry) in protected_ids:
            # Coherent-chain member: harder to dismiss -> escalate to a human
            # rather than accept the dismissal as a hard block.
            _raise_to(NEEDS_HUMAN)
            reasons.append(
                f"{title}: dismissed by the falsifier but is a member of a "
                "coherent kill chain -> escalated for human review, not dropped."
            )
        else:
            _raise_to(BLOCKED)
            blocked.append(title)
            reasons.append(
                f"{title}: dismissed -- an asserted identity anchor could not be "
                "re-derived from the evidence (possible hallucination)."
            )

    # Coverage gaps are ADVISORY, not blocking: a deliberately-partial analysis
    # (e.g. disk-only, no memory image supplied) is the normal case, so flagging
    # it must not force a non-zero exit -- that would fire on nearly every real
    # --harden run and train the investigator to ignore the gate. Stamp it so the
    # gap is visible; leave the verdict (and thus the exit code) to finding-level
    # causes only.
    advisories: list[str] = []
    not_examined = (coverage or {}).get("not_examined") or []
    if not_examined:
        advisories.append(
            "Coverage gap: important artifact class(es) not examined this run "
            f"({', '.join(not_examined)}); their silence is not a clean result."
        )

    return GateVerdict(
        verdict=verdict,
        reasons=tuple(reasons),
        blocked_findings=tuple(blocked),
        advisories=tuple(advisories),
    )
