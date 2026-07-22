"""Shared finding-hardening pipeline (execution-path convergence).

Both execution paths - the multi-agent orchestrator AND the recall scenario
harness - route their findings through this one module, so the integrity /
anti-hallucination guarantees ride the SAME path as the F1=1.00 recall result
instead of a separate demo fixture. Hardening is strictly additive metadata: it
records receipts, verdict clamps, tool-semantics checks, and a confirmed MITRE
matrix WITHOUT adding, dropping, or renaming any finding - so detection accuracy
(precision/recall/F1) is provably unaffected.

Per finding it produces:
- ``severity``: after the verdict rank clamp (single-source cap + engine ceiling).
- ``receipt``: an HMAC-SHA256 receipt bound to the evidence-image SHA + tool.
- ``checks.tool_semantics``: refutation-seat verdict (single-source-scoped, so a
  corroborated finding is never spuriously flagged MISREAD_TOOL).

Plus a case-level ``mitre_confirmed`` matrix built ONLY from fired-detector tags.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .correlation.sql_timeline import correlate_timeline, find_contradictions
from .custody.receipt import ReceiptMinter
from .custody.signing import sign_finding
from .findings.verdict_guard import guard_finding
from .reporting.mitre_guardrail import confirmed_matrix
from .self_correction.adversarial import (
    EntailmentFalsifier,
    FalsifierStatus,
    RulesAdjudicator,
    run_adversarial_round,
)
from .self_correction.seats import adjudicate as seats_adjudicate

# Minimum distinct artifact sources for the refutation-seat premise ("a LONE tool
# cannot establish X") to NOT apply - i.e. a corroborated finding is exempt from
# the seat check, mirroring the orchestrator's calibrated behavior.
_CORROBORATION_MIN = 2

# Which forensic tool's semantics judge a finding, by its category. The seat
# check is only meaningful for single-source findings; corroborated ones are
# reported SUPPORTED regardless.
_CATEGORY_SEAT_TOOL = {
    "command_and_control": "netscan",
    "process_injection": "netscan",
    "timeline_tampering": "mft",
    "anti_forensics": "mft",
    "execution": "mft",
    "persistence": "mft",
}
_DEFAULT_SEAT_TOOL = "mft"


@dataclass
class HardeningReport:
    """Additive hardening metadata for one set of findings."""

    finding_count: int
    hardened: list[dict] = field(default_factory=list)
    mitre_confirmed: list[dict] = field(default_factory=list)
    mitre_unconfirmed: list[str] = field(default_factory=list)
    # Cross-artifact correlation over findings that carry timeline evidence.
    # correlations: same actor/target seen by different sources within a window.
    # contradictions: same actor, different event type, overlapping window ->
    # surfaced UNRESOLVED (never auto-resolved) for a verifier to adjudicate.
    correlations: list[dict] = field(default_factory=list)
    contradictions: list[dict] = field(default_factory=list)

    @property
    def receipts_minted(self) -> int:
        return sum(1 for h in self.hardened if h.get("receipt"))

    @property
    def signed_receipts(self) -> int:
        """Count of publicly-verifiable Ed25519 receipts (0 unless a key was set)."""
        return sum(1 for h in self.hardened if h.get("signed_receipt"))

    @property
    def tool_semantics_supported(self) -> int:
        return sum(
            1
            for h in self.hardened
            if h.get("checks", {}).get("tool_semantics") == "SUPPORTED"
        )

    def to_dict(self) -> dict:
        return {
            "finding_count": self.finding_count,
            "receipts_minted": self.receipts_minted,
            "tool_semantics_supported": self.tool_semantics_supported,
            "mitre_confirmed": self.mitre_confirmed,
            "mitre_unconfirmed": self.mitre_unconfirmed,
            "correlations": self.correlations,
            "contradictions": self.contradictions,
            "hardened": self.hardened,
        }


def _seat_tool_for(finding: Any) -> str:
    category = getattr(finding.category, "value", str(finding.category))
    return _CATEGORY_SEAT_TOOL.get(category, _DEFAULT_SEAT_TOOL)


def _tool_semantics(finding: Any) -> str:
    """Refutation-seat verdict, single-source-scoped.

    A corroborated (>=2 distinct source) finding carries the corroboration the
    seat rule assumes absent, so it is SUPPORTED and never spuriously refuted.
    """
    corroboration = len({s for s in finding.artifact_sources if s})
    if corroboration >= _CORROBORATION_MIN:
        return "SUPPORTED"
    claim = " ".join(finding.reasoning_chain) or finding.description
    return seats_adjudicate(_seat_tool_for(finding), claim)


def _timeline_events(findings: list[Any]) -> list[dict]:
    """Extract normalized timeline events from findings that carry them.

    A finding opts into cross-artifact correlation by putting a ``timeline``
    dict (ts/source/actor/target/type) in its evidence. Findings without one are
    simply skipped, so correlation is opportunistic and never required.
    """
    events: list[dict] = []
    for finding in findings:
        timeline = (getattr(finding, "evidence", None) or {}).get("timeline")
        if not isinstance(timeline, dict):
            continue
        if not timeline.get("ts") or not timeline.get("source"):
            continue
        events.append(
            {
                "ts": str(timeline.get("ts")),
                "source": str(timeline.get("source")),
                "actor": str(timeline.get("actor", "")),
                "target": str(timeline.get("target", "")),
                "type": str(timeline.get("type", "")),
                "raw": str(timeline.get("raw", "")),
            }
        )
    return events


def _identity_anchors(finding: Any) -> list[dict]:
    """Re-derivable identity anchors (IPs, PIDs) a finding asserts.

    These are the hard anchors an independent falsifier re-checks against RAW
    evidence: an IP/PID a finding claims must actually appear in the evidence the
    detector consumed, or the finding is hallucinated. Empty when none present.
    """
    evidence = getattr(finding, "evidence", None) or {}
    anchors: list[dict] = []
    for key in ("dst_ip", "foreign_addr"):
        value = evidence.get(key)
        if value:
            anchors.append({"path": key, "expected": str(value), "kind": "ipv4"})
    pid = evidence.get("pid")
    if pid is not None:
        anchors.append({"path": "pid", "expected": str(pid), "kind": "pid"})
    return anchors


def _adversarial_ruling(finding: Any, raw_evidence: str | None) -> dict:
    """Adjudicate one finding with an INDEPENDENT re-derivation falsifier.

    The falsifier re-derives the finding's asserted identity anchors against the
    RAW evidence text the detector consumed (``raw_evidence``) - NOT the finding's
    own narrative - so a hallucinated anchor is killed even if the finding's
    reasoning also cites it. When no anchors are present, or no raw evidence is
    supplied for this finding, the independent check does not apply and we do not
    claim independence (family stays non-'entailment-rederivation').
    """
    anchors = _identity_anchors(finding)
    corroboration = len({s for s in finding.artifact_sources if s})
    if anchors and raw_evidence is not None:
        falsifier: Any = EntailmentFalsifier(
            asserted_values=anchors, evidence_text=raw_evidence
        )
    else:
        # No independent re-derivation possible: fall back to a null falsifier
        # (SURVIVED) so a well-formed finding is judged on corroboration, never
        # dismissed for lack of an independence signal.
        falsifier = _NullFalsifier()
    result = run_adversarial_round(
        claim=" ".join(finding.reasoning_chain) or finding.description,
        evidence_handles=[],
        falsifier=falsifier,
        analyst_verdict="confirmed",
        corroborating_sources=corroboration,
        analyst_model_family="home-analyst",
        adjudicator=RulesAdjudicator(),
    )
    return {
        "outcome": result.verdict.outcome,
        "falsifier_status": result.verdict.falsifier_status,
        "falsifier_family": result.falsifier_model_family,
        "architectural_distance": result.architectural_distance,
    }


class _NullFalsifier:
    """A falsifier that always SURVIVES (no independent signal available)."""

    @property
    def model_family(self) -> str:
        return "null-no-independent-evidence"

    def challenge(self, claim: str, evidence_handles: list[str]) -> FalsifierStatus:
        return FalsifierStatus.SURVIVED


def harden_findings(
    findings: list[Any],
    image_sha256: str,
    receipt_key: bytes,
    tool: str = "engine",
    signing_key: bytes | None = None,
    evidence_texts: dict[str, str] | None = None,
) -> HardeningReport:
    """Apply the additive hardening pipeline to a list of findings.

    Args:
        findings: The Finding objects a detection run produced.
        image_sha256: SHA-256 binding receipts to this run's evidence.
        receipt_key: Per-run HMAC key (>=32 bytes) for finding receipts.
        tool: Provenance label recorded in each receipt.
        signing_key: Optional Ed25519 private-key PEM. When provided, each finding
            also gets a publicly-verifiable ``signed_receipt`` (verifiable with
            only the embedded public key, no shared secret). When None, behavior
            and output are unchanged - the signed receipt is simply absent.
        evidence_texts: Optional map of finding-title -> RAW evidence text the
            detector consumed. When supplied, the adversarial pass re-derives a
            finding's asserted identity anchors (IP/PID) against this raw text -
            NOT the finding's own narrative - so a hallucinated anchor is killed
            independently. When absent for a finding, no independence is claimed.

    Returns:
        A HardeningReport with one hardened entry per finding (severity after
        clamp, HMAC receipt, optional Ed25519 signed receipt, tool-semantics
        check, adversarial ruling) plus the confirmed MITRE matrix. The finding
        set is never mutated: a clamp returns a copy, and the count is preserved,
        so precision/recall/F1 are unaffected.
    """
    minter = ReceiptMinter(key=receipt_key, image_sha256=image_sha256)
    evidence_texts = evidence_texts or {}
    hardened: list[dict] = []

    for finding in findings:
        # Verdict clamp: the detector's own severity is the engine ceiling, so
        # this enforces the single-source corroboration cap. Returns a copy.
        clamped = guard_finding(finding, engine_ceiling=finding.severity)
        finding_dict = clamped.to_dict()
        receipt = minter.mint(finding_dict, tool=tool)
        # Optional publicly-verifiable Ed25519 receipt (public-key, no shared
        # secret needed to verify) alongside the symmetric HMAC receipt.
        signed_receipt = (
            sign_finding(finding_dict, signing_key, image_sha256, tool)
            if signing_key is not None
            else None
        )
        # Adversarial pass with INDEPENDENT re-derivation against raw evidence
        # (keyed by the clamped finding's title, matching evidence_texts).
        adversarial = _adversarial_ruling(clamped, evidence_texts.get(clamped.title))
        hardened.append(
            {
                "finding": finding_dict,
                "receipt": receipt,
                "signed_receipt": signed_receipt,
                "checks": {"tool_semantics": _tool_semantics(clamped)},
                "adversarial": adversarial,
            }
        )

    mitre = confirmed_matrix([h["finding"] for h in hardened])

    # Cross-artifact correlation over any findings carrying timeline evidence.
    # Contradictions are surfaced UNRESOLVED (never auto-resolved), consistent
    # with the correlation module's contract. Empty when no finding opts in.
    events = _timeline_events(findings)
    correlations = [
        {"a": c.a, "b": c.b, "relation": c.relation} for c in correlate_timeline(events)
    ]
    contradictions = find_contradictions(events)

    return HardeningReport(
        finding_count=len(findings),
        hardened=hardened,
        mitre_confirmed=mitre.confirmed,
        mitre_unconfirmed=mitre.unconfirmed,
        correlations=correlations,
        contradictions=contradictions,
    )
