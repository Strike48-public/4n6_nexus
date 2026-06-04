"""Adapter: self-correction engine Findings -> A2A Verification records.

The dfir-verifier agent challenges analyst findings using the existing
self_correction engine, whose output (a ``Finding`` carrying contradictions,
resolutions, and a confidence calculation) must be expressed as the A2A
``Verification`` record defined in analysis/A2A_MESSAGE_SCHEMA.md so the
self-correction loop lands in the audit trail and is judge-traceable.

Phase A scope: the engine only produces disk/timeline (and exfil-correlation)
contradictions, so the verification ``domain`` is reported as ``disk_timeline``.
Memory/network domains are added in Phase B.
"""

from __future__ import annotations

from typing import Optional

from ..audit.models import Verification
from ..findings.finding import Finding
from .contradiction_detector import ContradictionType

# Which A2A verification domain each contradiction type belongs to. Types not
# listed here default to ``disk_timeline`` (the original Phase A domain).
_DOMAIN_BY_CONTRADICTION: dict[str, str] = {
    ContradictionType.EXFIL_CORRELATION.value: "exfil",
    ContradictionType.MEMORY_PRESENCE_MISMATCH.value: "memory",
    ContradictionType.NETWORK_PRESENCE_MISMATCH.value: "network",
}


def _domain_for(finding: Finding) -> str:
    """Report the A2A domain from the finding's primary contradiction type.

    A finding is domain-classified by its *first* contradiction. The engine
    builds one finding per contradiction source (causality, exfil, memory),
    so mixed-type findings do not arise today; if they ever do, the first
    contradiction wins. Findings with no contradiction stay ``disk_timeline``
    (the original Phase A default).
    """
    if not finding.contradictions:
        return "disk_timeline"
    primary = finding.contradictions[0].type.value
    return _DOMAIN_BY_CONTRADICTION.get(primary, "disk_timeline")


def _verdict_for(finding: Finding) -> str:
    """Map a finding's contradiction/resolution state to a verification verdict."""
    if not finding.contradictions:
        return "confirmed"
    if finding.resolutions:
        return "contradiction_resolved"
    return "contradiction_detected"


def _sum_impact(finding: Finding) -> float:
    """Total confidence penalty from all contradictions (negative)."""
    return sum(getattr(c, "confidence_impact", 0.0) for c in finding.contradictions)


def _sum_recovery(finding: Finding) -> float:
    """Total confidence recovery from all resolutions (positive)."""
    return sum(getattr(r, "confidence_recovery", 0.0) for r in finding.resolutions)


def finding_to_verification(
    finding: Finding,
    finding_id: str,
    tiebreaker_tool_invocations: Optional[list[str]] = None,
    challenge_message_id: Optional[str] = None,
) -> Verification:
    """Translate a self-correction Finding into an A2A Verification record.

    Args:
        finding: The Finding produced by the self-correction engine.
        finding_id: The A2A id of the finding being verified.
        tiebreaker_tool_invocations: entry_ids of any tiebreaker tool calls
            (e.g. the Event Log 4688 lookup) made during resolution.
        challenge_message_id: entry_id of the verifier's challenge message.

    Returns:
        A Verification populated from the finding's self-correction metadata.
    """
    calc = finding.confidence_calculation or {}
    confidence_before = calc.get("initial_confidence", finding.confidence)
    confidence_after = calc.get("final_confidence", finding.confidence)

    contradiction_type = (
        finding.contradictions[0].type.value if finding.contradictions else None
    )

    reasoning = None
    if finding.reasoning_chain:
        reasoning = " ".join(finding.reasoning_chain)
    elif finding.contradictions:
        reasoning = finding.contradictions[0].description

    return Verification(
        finding_id=finding_id,
        verifier="verifier",
        verdict=_verdict_for(finding),
        domain=_domain_for(finding),
        confidence_before=confidence_before,
        confidence_after=confidence_after,
        contradiction_type=contradiction_type,
        confidence_delta=_sum_impact(finding),
        recovery_delta=_sum_recovery(finding),
        tiebreaker_tool_invocations=tiebreaker_tool_invocations or [],
        challenge_message_id=challenge_message_id,
        reasoning=reasoning,
    )
