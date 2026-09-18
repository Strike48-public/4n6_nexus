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

import logging
from dataclasses import dataclass, field
from typing import Any

from .correlation.assemble import build_correlation
from .custody import merkle
from .custody.receipt import ReceiptMinter
from .custody.signing import (
    resolve_signing_key,
    sign_finding,
)
from .findings.risk_scoring import score_subject_risk
from .findings.verdict_guard import guard_finding
from .injection_defense.ledger import build_injection_ledger
from .coverage.harden_coverage import harden_coverage
from .reporting.mitre_guardrail import confirmed_matrix
from .self_correction.gate import build_gate
from .self_correction.adversarial import (
    EntailmentFalsifier,
    FalsifierStatus,
    RulesAdjudicator,
    run_adversarial_round,
)
from .self_correction.hypothesis_ledger import build_hypothesis_ledger
from .self_correction.seats import adjudicate as seats_adjudicate

logger = logging.getLogger(__name__)

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
    # co_occurrences: same actor, different event type, overlapping window ->
    # a corroborating same-actor multi-behavior overlap (SFE-nh4h), NOT a conflict
    # (the detector cannot distinguish a genuine contradiction from reinforcement).
    correlations: list[dict] = field(default_factory=list)
    co_occurrences: list[dict] = field(default_factory=list)
    # Entity-keyed cross-artifact corroboration (SFE-fx8o): a canonical entity
    # evidenced by >=2 distinct artifact sources (e.g. one process seen by MFT,
    # Prefetch AND EventLog). Distinct from ``correlations`` (memory-only,
    # time-window, timeline-opt-in): this joins ALL findings on the shared
    # canonical_entity key. Empty when DuckDB is absent (optional dep).
    corroborations: list[dict] = field(default_factory=list)
    # Per-subject additive risk (SFE-kh4h wired by SFE-dkfr): findings grouped by
    # canonical entity, weak signals accumulated into a banded CRITICAL/HIGH/
    # MEDIUM/LOW score with CRITICAL gated behind >=2 distinct artifact sources.
    # A read-only overlay over the emitted findings (never re-scores them), sorted
    # highest-risk first; each entry is a SubjectRisk.to_dict().
    subject_risk: list[dict] = field(default_factory=list)
    # Set-level integrity (SFE-cahy). merkle_root folds every finding hash into
    # one value so add/remove/reorder of the finding set is detectable; anchor is
    # the Ed25519-signed, publicly-verifiable seal over that root (None on the
    # HMAC-only fallback path when cryptography is unavailable).
    merkle_root: str | None = None
    anchor: dict | None = None
    # True iff the Ed25519 signer was PINNED (env key), so receipts prove
    # provenance against a published public key rather than only internal
    # consistency under a fresh per-run key.
    signer_pinned: bool = False
    # Tamper-evident, counts-only injection ledger (SFE-q715): a genesis-anchored
    # SHA-256 hash chain of the prompt-injection attempts recorded in this run,
    # built from the sanitizer-emitted injection findings. Brings the scored path
    # to parity with the MCP path (which already logs attempts to the audit
    # chain). Empty when no injection attempt was recorded. Verify with
    # injection_defense.ledger.verify_injection_ledger.
    injection_ledger: list[dict] = field(default_factory=list)
    # Candidate-elimination / self-correction trail (SFE-fibx.1): the falsifiable
    # hypothesis ledger's report_summary -- confirmed/retracted/open hypotheses +
    # the ordered SelfCorrection trail. A read-only overlay produced by the SAME
    # builder the demo orchestrator uses, so a SUPPORTS->REFUTES retraction is now
    # a first-class field of the shipping hardened report (was demo-path only).
    # Honestly empty (zero corrections) on an all-confirmed run: an empty trail is
    # correct, not a failure. Never touches evidence['executable'], so F1 holds.
    hypothesis_ledger: dict = field(default_factory=dict)
    # Harden-path coverage audit (SFE-fibx.5 PR-B): the two honest coverage
    # signals for a parsed-input run -- ``uncited`` artifact classes (supplied +
    # parsed but cited by no finding: a blind spot) and ``not_examined``
    # high/critical classes whose evidence was not supplied (their silence is not
    # a clean bill). Empty when the caller supplies no coverage input (the F1
    # harness), so scoring is untouched. NOT the assess_coverage trichotomy, whose
    # gap axis is vacuous on already-parsed input.
    coverage: dict = field(default_factory=dict)
    # Report-blocking gate verdict (SFE-fibx.5 PR-D): composes the per-finding
    # adversarial outcome + kill-chain-coherence protection + the coverage audit
    # into PASS / NEEDS_HUMAN / BLOCKED with reasons. Computed only when the
    # caller declared supplied_classes (same gate as coverage), so the F1 harness
    # -- which supplies none -- carries an empty gate and is untouched. Advisory
    # data on the report; the EMITTERS enforce it (stamp + non-zero exit), never
    # harden_findings itself, so no finding is mutated or dropped.
    gate: dict = field(default_factory=dict)

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
            "co_occurrences": self.co_occurrences,
            "corroborations": self.corroborations,
            "subject_risk": self.subject_risk,
            "merkle_root": self.merkle_root,
            "anchor": self.anchor,
            "signer_pinned": self.signer_pinned,
            "injection_ledger": self.injection_ledger,
            "hypothesis_ledger": self.hypothesis_ledger,
            "coverage": self.coverage,
            "gate": self.gate,
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
    independent = bool(anchors) and raw_evidence is not None
    if independent:
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
        # Re-derivation inputs: recorded so a third party can INDEPENDENTLY
        # reproduce this ruling offline (tools/verify_verification.py) - the LLM-
        # free entailment challenge re-runs the anchors against the span, and the
        # adjudicator ladder re-runs over (falsifier_status, corroboration). Only
        # ``evidence_span`` is present when an independent check actually ran; on
        # the null-falsifier fallback it is None so the verifier knows no
        # independent re-derivation was claimed (and skips the entailment step).
        "anchors": anchors,
        "evidence_span": raw_evidence if independent else None,
        "corroboration": corroboration,
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
    supplied_classes: set[str] | None = None,
) -> HardeningReport:
    """Apply the additive hardening pipeline to a list of findings.

    Args:
        findings: The Finding objects a detection run produced.
        image_sha256: SHA-256 binding receipts to this run's evidence.
        receipt_key: Per-run HMAC key (>=32 bytes) for finding receipts.
        tool: Provenance label recorded in each receipt.
        signing_key: Ed25519 private-key PEM used to mint the publicly-verifiable
            ``signed_receipt`` per finding (verifiable with only the embedded
            public key, no shared secret). When None (the usual case), a fresh
            per-run keypair is generated so public-key receipts are the DEFAULT -
            provided ``cryptography`` is installed. When ``cryptography`` is
            absent (core install without the connector extra), the pipeline
            degrades to HMAC-only: ``signed_receipt`` is None and no anchor is
            minted. Detection output is identical in every case.
        evidence_texts: Optional map of finding-title -> RAW evidence text the
            detector consumed. When supplied, the adversarial pass re-derives a
            finding's asserted identity anchors (IP/PID) against this raw text -
            NOT the finding's own narrative - so a hallucinated anchor is killed
            independently. When absent for a finding, no independence is claimed.
        supplied_classes: Optional set of coarse artifact classes whose evidence
            was supplied+parsed this run (see ``coverage.harden_coverage``). When
            given, the report carries a coverage audit (uncited blind spots +
            not-examined important classes). When None (e.g. the F1 harness), the
            coverage field stays empty and scoring is untouched.

    Returns:
        A HardeningReport with one hardened entry per finding (severity after
        clamp, HMAC receipt, publicly-verifiable Ed25519 receipt by default,
        tool-semantics check, adversarial ruling), plus the confirmed MITRE
        matrix, a Merkle root over the finding set, and a signed run anchor. The
        finding set is never mutated: a clamp returns a copy, and the count is
        preserved, so precision/recall/F1 are unaffected.
    """
    minter = ReceiptMinter(key=receipt_key, image_sha256=image_sha256)
    evidence_texts = evidence_texts or {}
    hardened: list[dict] = []

    # Ed25519 public-key receipts are the DEFAULT emission path: mint a per-run
    # key when the caller did not supply one, so every finding is publicly
    # verifiable offline without a shared secret. The whole feature is gated on
    # the optional ``cryptography`` package - absent it, we fall back to HMAC-only
    # (no signed receipt, no anchor) so the core package still runs.
    run_signing_key = signing_key
    signer_pinned = False
    if run_signing_key is None:
        run_signing_key, signer_pinned = resolve_signing_key()

    for finding in findings:
        # Verdict clamp: the detector's own severity is the engine ceiling, so
        # this enforces the single-source corroboration cap. Returns a copy.
        clamped = guard_finding(finding, engine_ceiling=finding.severity)
        finding_dict = clamped.to_dict()
        receipt = minter.mint(finding_dict, tool=tool)
        # Publicly-verifiable Ed25519 receipt (public-key, no shared secret to
        # verify) alongside the symmetric HMAC receipt. Default path unless
        # cryptography is unavailable, in which case run_signing_key is None.
        signed_receipt = (
            sign_finding(finding_dict, run_signing_key, image_sha256, tool)
            if run_signing_key is not None
            else None
        )
        # Adversarial pass with INDEPENDENT re-derivation against raw evidence
        # (keyed by the clamped finding's title, matching evidence_texts). When the
        # caller supplied no explicit text for this finding, fall back to the
        # finding's OWN source_span -- the exact tool-output record it was derived
        # from (SFE-fsno). This activates the independent EntailmentFalsifier on the
        # shipping analyze --harden path, which otherwise passed no evidence_texts
        # and always hit the null falsifier (a vacuous SURVIVED). The span is
        # per-finding, so a hallucinated/misattributed anchor is FALSIFIED because
        # it is absent from its own provenance -- never a merged-corpus blob, which
        # would pass vacuously (SFE-fibx.6).
        raw_evidence = evidence_texts.get(clamped.title)
        if raw_evidence is None:
            raw_evidence = clamped.evidence.get("source_span")
        adversarial = _adversarial_ruling(clamped, raw_evidence)
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

    # Cross-artifact correlation (timeline edges + co-occurrences + entity-keyed
    # corroboration) is assembled by the shared read-only unit (SFE-fibx.10) so the
    # live/session ``pivot`` path computes it identically to this harden report.
    # Additive over true findings (none added/dropped/re-scored); corroboration is
    # empty when DuckDB is unavailable (optional dependency).
    _correlation = build_correlation(findings)
    correlations = _correlation.correlations
    co_occurrences = _correlation.co_occurrences
    corroborations = _correlation.corroborations

    # Per-subject additive risk: accumulate the emitted findings' weak signals by
    # canonical entity into banded subject risk (CRITICAL gated behind >=2 distinct
    # artifact sources). Pure overlay over the SAME findings the report already
    # carries, so no finding is added/dropped/re-scored and F1 is unaffected.
    # Scored off the raw ``findings`` (not ``hardened``'s clamped copies) on
    # purpose: score_subject_risk reads confidence/category/artifact_sources only,
    # none of which guard_finding touches (it clamps severity), so the clamp is
    # irrelevant here and the raw list avoids rebuilding Finding objects.
    subject_risk = [s.to_dict() for s in score_subject_risk(findings)]

    # Candidate-elimination overlay (SFE-fibx.1): build the falsifiable-hypothesis
    # ledger from the SAME findings, so a self-correction retraction (a benign-infra
    # exoneration flips SUPPORTS -> REFUTES) is a first-class field of the shipping
    # hardened report -- not demo-orchestrator-only. Read-only over the emitted
    # findings (never re-scored), so F1 is unaffected. Findings on this path carry
    # no separate tool-exec id, so each cites its own identity (title) as the
    # required citation -- the same fallback the orchestrator uses for a tool-less
    # analyst finding.
    hypothesis_ledger = build_hypothesis_ledger(
        [(f, f.title or f"finding-{i}") for i, f in enumerate(findings)]
    ).report_summary()

    # Harden-path coverage audit (SFE-fibx.5 PR-B): only when the caller declared
    # which artifact classes it supplied. Read-only over the findings' artifact
    # sources; empty (no coverage claim) otherwise, so the F1 harness -- which
    # supplies no classes -- is untouched.
    coverage = (
        harden_coverage(findings, supplied_classes=supplied_classes).to_dict()
        if supplied_classes is not None
        else {}
    )

    # Report-blocking gate (SFE-fibx.5 PR-D): compose the per-finding adversarial
    # outcomes (already in ``hardened``) + kill-chain-coherence protection + the
    # coverage audit into a PASS / NEEDS_HUMAN / BLOCKED verdict. Gated on the same
    # supplied_classes signal as coverage so the F1 harness carries an empty gate.
    # Advisory only here -- the emitters enforce it; harden_findings never mutates
    # or drops a finding, so F1 is untouched. Proven negatives are not emitted on
    # this path (demo/CLI only), so none are passed.
    gate = (
        build_gate(hardened, coverage=coverage, negatives=[]).to_dict()
        if supplied_classes is not None
        else {}
    )

    # Set-level integrity: fold every finding's identity hash into one Merkle
    # root, then bind that root to the evidence image under the run key. Anyone
    # can later prove offline that exactly this set of findings was emitted for
    # this image - no additions, deletions, or reorderings. Only minted when
    # public-key receipts are (i.e. cryptography is present).
    merkle_root: str | None = None
    anchor: dict | None = None
    if run_signing_key is not None:
        finding_hashes = [
            h["signed_receipt"]["finding_hash"]
            for h in hardened
            if h.get("signed_receipt")
        ]
        merkle_root = merkle.merkle_root(finding_hashes)
        anchor = merkle.mint_anchor(
            merkle_root, image_sha256, len(finding_hashes), run_signing_key
        )

    return HardeningReport(
        finding_count=len(findings),
        hardened=hardened,
        mitre_confirmed=mitre.confirmed,
        mitre_unconfirmed=mitre.unconfirmed,
        correlations=correlations,
        co_occurrences=co_occurrences,
        corroborations=corroborations,
        subject_risk=subject_risk,
        merkle_root=merkle_root,
        anchor=anchor,
        signer_pinned=signer_pinned,
        injection_ledger=build_injection_ledger(findings),
        hypothesis_ledger=hypothesis_ledger,
        coverage=coverage,
        gate=gate,
    )


def lite_harden(findings: list[Any]) -> tuple[list[Any], list[dict]]:
    """Cheap, correctness-critical harden for the interactive connector/GUI seam.

    The full :func:`harden_findings` overlay (HMAC + Ed25519 receipts, Merkle
    anchor, DuckDB correlation, MITRE matrix) is too heavy to run on every
    interactive request, so the live connector path historically returned RAW
    detector findings -- which can show a HIGHER, un-clamped severity than the
    defensible scored path and carry no triage signal (SFE-i596). This applies
    only the two halves that are both cheap AND correctness-relevant:

      1. the verdict clamps (``guard_finding``): severity ceiling + single-source
         cap, so a lone-source finding cannot present above its defensible
         severity pending corroboration -- the GUI shows the SAME severities the
         scored path would, not raw detector output; and
      2. the per-subject RISK overlay (``score_subject_risk``): banded CRITICAL/
         HIGH/MEDIUM/LOW triage ("look at this subject first").

    It deliberately does NOT sign receipts, mint an anchor, or run correlation;
    those custody-chain features stay on the ``analyze --harden`` CLI path. F1 is
    unaffected: clamps re-derive SEVERITY only (never ``evidence['executable']``,
    the detection scoring key), and risk is a read-only overlay.

    Returns ``(clamped_findings, subject_risk)`` where ``clamped_findings`` are
    Finding objects (the caller serializes them) and ``subject_risk`` is a list of
    ``SubjectRisk.to_dict()`` mappings, highest-risk first. Inputs are not mutated
    (``guard_finding`` returns a copy when it changes anything).
    """
    clamped = [guard_finding(f, engine_ceiling=f.severity) for f in findings]
    # Risk is scored off the CLAMPED findings so the triage signal is consistent
    # with the severities the caller will render; score_subject_risk reads
    # confidence/category/artifact_sources (unchanged by the clamp), so this is
    # equivalent to scoring the raw findings but avoids any future divergence.
    subject_risk = [s.to_dict() for s in score_subject_risk(clamped)]
    return clamped, subject_risk
