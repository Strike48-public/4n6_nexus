"""Adversarial verification: falsifier protocol + deterministic adjudicator.

Gallery idea #8 - the highest-impact verification gap the field identified. The
shared insight across MR. Robot Adversarial, The Tribunal, Council-SIFT, GLASSBOX
and Glass Box is: **you cannot fix hallucination by cooperative self-review, only
adversarially, and the final verdict must be produced by a deterministic rule
ladder rather than an LLM judge.**

This module provides the model-free core:

  * ``Falsifier`` - a protocol for an agent whose job is to KILL a finding. In
    production it is backed by a model from a DIFFERENT family than the analyst
    (so it fails differently) and is given only the claim + evidence handles,
    never the analyst's reasoning. In CI it is a deterministic stub.
  * ``RulesAdjudicator`` - a pure, deterministic rule ladder that consumes
    (analyst verdict, falsifier status, corroboration) and produces
    sustained / dismissed / remanded / flagged_human. It is ADDITIVE-ONLY: the
    falsifier can bounce a finding but never rescue one, and a bounded remand
    loop degrades to human review rather than looping forever.

Wire this behind an env flag in the orchestrator so the F1=1.00 baseline is
untouched when disabled.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Protocol, runtime_checkable

# Analyst verdicts that assert the finding is real (eligible to be sustained).
# A finding the analyst already doubts cannot be upgraded by a falsifier.
_AFFIRMATIVE_ANALYST_VERDICTS = frozenset({"confirmed", "contradiction_resolved"})

# Minimum distinct corroborating artifact sources required to sustain.
_MIN_CORROBORATION = 2


class FalsifierStatus(str, Enum):
    """Outcome of a falsifier's attempt to refute a finding."""

    SURVIVED = "survived"  # the falsifier could not kill it
    FALSIFIED = "falsified"  # the falsifier refuted it
    INCONCLUSIVE = "inconclusive"  # the falsifier could not decide


@runtime_checkable
class Falsifier(Protocol):
    """An adversary that tries to refute a finding.

    Implementations receive ONLY the claim text and opaque evidence handles
    (audit-log entry ids), never the analyst's reasoning, and should be prompted
    to default to FALSIFIED when uncertain.
    """

    @property
    def model_family(self) -> str:
        """The model family backing this falsifier (for architectural distance)."""
        ...

    def challenge(self, claim: str, evidence_handles: list[str]) -> FalsifierStatus:
        """Attempt to refute the claim; return the resulting status."""
        ...


class EntailmentFalsifier:
    """A falsifier that re-derives a finding's asserted values from raw evidence.

    Unlike the deterministic refutation SEATS (which reason about tool semantics
    over the analyst's own claim text), this falsifier is INDEPENDENT of the
    analyst's reasoning: it re-checks the concrete values a finding asserts
    (hashes, IPs, PIDs, filenames) directly against the raw evidence text via the
    entailment engine. If an identity anchor the finding claims does not actually
    appear in the evidence, the finding is FALSIFIED - a hallucinated value has no
    evidence to stand on. This is the reproducible, deterministic stand-in for a
    rival-model falsifier: independence via re-derivation, not a second live LLM.

    - FALSIFIED: an asserted value is not entailed by the evidence.
    - SURVIVED: all asserted values are re-derivable from the evidence.
    - INCONCLUSIVE: the finding asserts no checkable values (cannot decide).
    """

    def __init__(self, asserted_values: list[dict], evidence_text: str):
        self._asserted_values = asserted_values
        self._evidence_text = evidence_text

    @property
    def model_family(self) -> str:
        # A distinct "family" from any analyst so architectural_distance is 1.0:
        # the check derives from evidence bytes, not the analyst's model.
        return "entailment-rederivation"

    def challenge(self, claim: str, evidence_handles: list[str]) -> FalsifierStatus:
        # Imported lazily to keep this module import-light for callers that never
        # use the entailment falsifier.
        from ..findings.entailment import check_entailment

        if not self._asserted_values:
            return FalsifierStatus.INCONCLUSIVE
        report = check_entailment(self._asserted_values, self._evidence_text)
        return (
            FalsifierStatus.SURVIVED
            if report.all_supported
            else FalsifierStatus.FALSIFIED
        )


@dataclass(frozen=True)
class AdjudicatedVerdict:
    """The deterministic adjudicator's ruling on a single finding."""

    outcome: str  # sustained | dismissed | remanded | flagged_human
    rationale: str
    falsifier_status: str


@dataclass(frozen=True)
class AdversarialRoundResult:
    """One adversarial round: the ruling plus the audit-relevant provenance."""

    verdict: AdjudicatedVerdict
    falsifier_model_family: str
    architectural_distance: float  # 1.0 if falsifier family != analyst family


class RulesAdjudicator:
    """Deterministic rule ladder mapping inputs to a final verdict.

    Not an LLM judge - the ordering of rules is the whole point:
    1. FALSIFIED           -> dismissed (the adversary killed it)
    2. not affirmative     -> remanded  (analyst already doubts it; never sustain)
    3. INCONCLUSIVE        -> remanded  (adversary could not decide)
    4. SURVIVED + >=2 srcs -> sustained (survived AND independently corroborated)
    5. SURVIVED + <2 srcs  -> remanded  (survived but uncorroborated)
    A finding at or beyond the remand cap degrades to flagged_human.
    """

    def __init__(self, max_remands: int = 2):
        self.max_remands = max_remands

    def adjudicate(
        self,
        analyst_verdict: str,
        falsifier_status: FalsifierStatus,
        corroborating_sources: int,
        remand_count: int = 0,
    ) -> AdjudicatedVerdict:
        """Return the deterministic ruling for one finding."""
        fs = falsifier_status.value

        if falsifier_status is FalsifierStatus.FALSIFIED:
            return AdjudicatedVerdict(
                "dismissed",
                "Falsifier refuted the finding; additive-only rule dismisses it.",
                fs,
            )

        # Anything that is not an outright sustain becomes a remand candidate; if
        # the finding has already exhausted its remands, escalate to a human.
        def _remand_or_human(reason: str) -> AdjudicatedVerdict:
            if remand_count >= self.max_remands:
                return AdjudicatedVerdict(
                    "flagged_human",
                    f"{reason} Remand budget exhausted -> flagged for human review.",
                    fs,
                )
            return AdjudicatedVerdict("remanded", reason, fs)

        if analyst_verdict not in _AFFIRMATIVE_ANALYST_VERDICTS:
            return _remand_or_human(
                "Analyst verdict is not affirmative; a falsifier cannot rescue it."
            )

        if falsifier_status is FalsifierStatus.INCONCLUSIVE:
            return _remand_or_human("Falsifier was inconclusive.")

        # SURVIVED from here.
        if corroborating_sources >= _MIN_CORROBORATION:
            return AdjudicatedVerdict(
                "sustained",
                f"Survived adversarial challenge with {corroborating_sources} "
                "corroborating sources.",
                fs,
            )
        return _remand_or_human(
            "Survived the falsifier but lacks independent corroboration "
            f"({corroborating_sources} < {_MIN_CORROBORATION})."
        )


def run_adversarial_round(
    claim: str,
    evidence_handles: list[str],
    falsifier: Falsifier,
    analyst_verdict: str,
    corroborating_sources: int,
    analyst_model_family: str,
    remand_count: int = 0,
    adjudicator: RulesAdjudicator | None = None,
) -> AdversarialRoundResult:
    """Run one adversarial round and adjudicate it deterministically.

    The falsifier sees only ``claim`` + ``evidence_handles`` (never the analyst's
    reasoning). Architectural distance is 1.0 when the falsifier is from a
    different model family than the analyst - the property that makes the
    challenge meaningful - and is recorded for the audit log.
    """
    adjudicator = adjudicator or RulesAdjudicator()
    status = falsifier.challenge(claim, evidence_handles)
    verdict = adjudicator.adjudicate(
        analyst_verdict=analyst_verdict,
        falsifier_status=status,
        corroborating_sources=corroborating_sources,
        remand_count=remand_count,
    )
    distance = 1.0 if falsifier.model_family != analyst_model_family else 0.0
    return AdversarialRoundResult(
        verdict=verdict,
        falsifier_model_family=falsifier.model_family,
        architectural_distance=distance,
    )
