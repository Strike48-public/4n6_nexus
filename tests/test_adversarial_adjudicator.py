"""Tests for adversarial verification: falsifier protocol + deterministic adjudicator.

Gallery idea #8. Replaces cooperative single-engine self-review with an
adversarial layer: a falsifier (from a different model family in production, a
deterministic stub in CI) tries to KILL each finding, and a DETERMINISTIC rule
ladder - not an LLM judge - consumes (analyst verdict, falsifier status,
corroboration) to produce the final verdict. Additive-only: the falsifier can
bounce a finding but never rescue one.

The adjudicator is pure code, so it is fully CI-testable. RED-first: the module
did not exist before.
"""

import pytest

from sift_find_evil.self_correction.adversarial import (
    AdjudicatedVerdict,
    FalsifierStatus,
    Falsifier,
    RulesAdjudicator,
    run_adversarial_round,
)


class _StubFalsifier(Falsifier):
    """Deterministic falsifier for tests: returns a scripted status."""

    def __init__(self, status: FalsifierStatus, model_family: str = "stub-family"):
        self._status = status
        self._family = model_family

    @property
    def model_family(self) -> str:
        return self._family

    def challenge(self, claim: str, evidence_handles: list[str]) -> FalsifierStatus:
        return self._status


def test_falsified_finding_is_dismissed():
    adj = RulesAdjudicator()
    v = adj.adjudicate(
        analyst_verdict="confirmed",
        falsifier_status=FalsifierStatus.FALSIFIED,
        corroborating_sources=2,
    )
    assert v.outcome == "dismissed"


def test_survived_and_corroborated_is_sustained():
    adj = RulesAdjudicator()
    v = adj.adjudicate(
        analyst_verdict="confirmed",
        falsifier_status=FalsifierStatus.SURVIVED,
        corroborating_sources=2,
    )
    assert v.outcome == "sustained"


def test_survived_but_single_source_is_remanded():
    # Survives the falsifier but lacks independent corroboration -> not sustained.
    adj = RulesAdjudicator()
    v = adj.adjudicate(
        analyst_verdict="confirmed",
        falsifier_status=FalsifierStatus.SURVIVED,
        corroborating_sources=1,
    )
    assert v.outcome == "remanded"


def test_inconclusive_falsifier_remands():
    adj = RulesAdjudicator()
    v = adj.adjudicate(
        analyst_verdict="confirmed",
        falsifier_status=FalsifierStatus.INCONCLUSIVE,
        corroborating_sources=2,
    )
    assert v.outcome == "remanded"


def test_falsifier_can_bounce_but_never_rescue():
    # Analyst already said 'contradiction_detected' (not confirmed). A SURVIVED
    # falsifier must not upgrade it to sustained - additive-only.
    adj = RulesAdjudicator()
    v = adj.adjudicate(
        analyst_verdict="contradiction_detected",
        falsifier_status=FalsifierStatus.SURVIVED,
        corroborating_sources=3,
    )
    assert v.outcome != "sustained"


def test_remand_exhaustion_degrades_to_flagged_human():
    adj = RulesAdjudicator(max_remands=1)
    v1 = adj.adjudicate(
        analyst_verdict="confirmed",
        falsifier_status=FalsifierStatus.INCONCLUSIVE,
        corroborating_sources=2,
        remand_count=1,  # already remanded once, at the cap
    )
    assert v1.outcome == "flagged_human"


def test_run_round_records_model_family_and_distance():
    # A falsifier from a different family than the analyst has architectural
    # distance 1.0; the round result records it for the audit log.
    falsifier = _StubFalsifier(FalsifierStatus.SURVIVED, model_family="rival-family")
    result = run_adversarial_round(
        claim="evil.exe executed at 03:00",
        evidence_handles=["evt-000012"],
        falsifier=falsifier,
        analyst_verdict="confirmed",
        corroborating_sources=2,
        analyst_model_family="home-family",
    )
    assert result.verdict.outcome == "sustained"
    assert result.falsifier_model_family == "rival-family"
    assert result.architectural_distance == 1.0


def test_same_family_falsifier_has_zero_distance():
    falsifier = _StubFalsifier(FalsifierStatus.SURVIVED, model_family="home-family")
    result = run_adversarial_round(
        claim="c",
        evidence_handles=["evt-1"],
        falsifier=falsifier,
        analyst_verdict="confirmed",
        corroborating_sources=2,
        analyst_model_family="home-family",
    )
    assert result.architectural_distance == 0.0


def test_verdict_is_immutable_dataclass():
    v = AdjudicatedVerdict(
        outcome="sustained", rationale="x", falsifier_status="survived"
    )
    with pytest.raises(Exception):
        v.outcome = "dismissed"  # frozen
