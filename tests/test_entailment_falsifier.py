"""Independent evidence-re-derivation falsifier (move #5).

Closes the "single-engine verification" gap the positioning audit flagged: the
reproducible path's falsifier was refutation SEATS over the same tool output -
functionally a sibling of the guardrails, not independent cross-examination.

The EntailmentFalsifier is genuinely independent of the analyst's reasoning: it
re-derives the finding's ASSERTED VALUES (hashes, IPs, PIDs, filenames) directly
against the raw evidence text via the entailment engine, and FALSIFIES when an
identity anchor the finding claims does not actually appear in the evidence. It
is deterministic and CI-reproducible - independence, not a second live LLM.

RED-first: EntailmentFalsifier did not exist.
"""

from sift_find_evil.self_correction.adversarial import (
    FalsifierStatus,
    EntailmentFalsifier,
    run_adversarial_round,
    RulesAdjudicator,
)


def test_falsifies_when_asserted_value_absent_from_evidence():
    # The finding claims IP 10.0.0.9, but the raw evidence never mentions it.
    f = EntailmentFalsifier(
        asserted_values=[{"path": "dst_ip", "expected": "10.0.0.9", "kind": "ipv4"}],
        evidence_text="netscan shows a socket to 203.0.113.5:443",
    )
    assert f.challenge("hardcoded C2 to 10.0.0.9", ["evt-000001"]) == (
        FalsifierStatus.FALSIFIED
    )


def test_survives_when_asserted_value_present_in_evidence():
    f = EntailmentFalsifier(
        asserted_values=[{"path": "dst_ip", "expected": "203.0.113.5", "kind": "ipv4"}],
        evidence_text="netscan shows a socket to 203.0.113.5:443",
    )
    assert f.challenge("socket to 203.0.113.5", ["evt-000001"]) == (
        FalsifierStatus.SURVIVED
    )


def test_inconclusive_when_no_asserted_values_to_check():
    # Nothing to re-derive -> the falsifier cannot decide (must not fabricate a kill).
    f = EntailmentFalsifier(asserted_values=[], evidence_text="some text")
    assert f.challenge("a claim", ["evt-000001"]) == FalsifierStatus.INCONCLUSIVE


def test_model_family_marks_it_independent():
    f = EntailmentFalsifier(asserted_values=[], evidence_text="")
    # A distinct family from the analyst so architectural_distance registers as 1.0.
    assert f.model_family == "entailment-rederivation"


def test_independent_falsifier_kills_a_hallucinated_finding_end_to_end():
    # A finding asserting an IP absent from evidence is dismissed by the adjudicator.
    f = EntailmentFalsifier(
        asserted_values=[{"path": "dst_ip", "expected": "10.0.0.9", "kind": "ipv4"}],
        evidence_text="only 203.0.113.5 appears here",
    )
    result = run_adversarial_round(
        claim="C2 beacon to 10.0.0.9",
        evidence_handles=["evt-000001"],
        falsifier=f,
        analyst_verdict="confirmed",
        corroborating_sources=2,
        analyst_model_family="home-analyst",
        adjudicator=RulesAdjudicator(),
    )
    assert result.verdict.outcome == "dismissed"
    assert result.architectural_distance == 1.0  # independent family


def test_grounded_finding_sustains_under_independent_falsifier():
    f = EntailmentFalsifier(
        asserted_values=[{"path": "dst_ip", "expected": "203.0.113.5", "kind": "ipv4"}],
        evidence_text="socket to 203.0.113.5:443 observed",
    )
    result = run_adversarial_round(
        claim="socket to 203.0.113.5",
        evidence_handles=["evt-000001"],
        falsifier=f,
        analyst_verdict="confirmed",
        corroborating_sources=2,
        analyst_model_family="home-analyst",
        adjudicator=RulesAdjudicator(),
    )
    assert result.verdict.outcome == "sustained"
