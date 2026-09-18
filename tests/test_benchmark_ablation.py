"""Defenses OFF/ON ablation for the hallucination benchmark (SFE-i7l7 PR2).

The field's leaders publish an OFF/ON ablation: run the corpus with defenses
disabled vs enabled and report the marginal value of the defenses. This measures
the INJECTION defense specifically, because that is the defense with a scorable
effect on this deterministic engine.

Honest framing (verified empirically, not asserted): the deterministic engine
does NOT obey injected prose, so its hallucination_rate is 0 whether the sanitizer
is ON or OFF - a forced hallucination_rate delta here would be a meaningless 0. The
real, measurable value of the injection defense is DETECTION + NEUTRALIZATION: with
it ON, adversarial evidence text is detected (surfaced as an injection_attempt
finding) and neutralized (role tokens stripped, payload sentinel-wrapped); with it
OFF, the attempt passes through undetected and un-neutralized. The ablation reports
that neutralization delta as the headline and states the hallucination_rate=0
result plainly (it would become a live delta only on an LLM-analyst path).
"""

from __future__ import annotations

from pathlib import Path

from sift_find_evil.benchmark.ablation import run_injection_ablation

REPO_ROOT = Path(__file__).resolve().parents[1]


def test_ablation_reports_both_arms_and_a_neutralization_delta():
    report = run_injection_ablation(REPO_ROOT)
    for key in (
        "attempts_neutralized_on",
        "attempts_neutralized_off",
        "neutralization_delta",
        "hallucination_rate_on",
        "hallucination_rate_off",
    ):
        assert key in report, f"ablation report missing {key!r}"


def test_defenses_on_neutralizes_more_than_off():
    # The headline: with the injection defense ON, at least one adversarial attempt
    # is detected+neutralized that OFF lets through. Defenses must never neutralize
    # FEWER attempts than OFF.
    report = run_injection_ablation(REPO_ROOT)
    assert report["attempts_neutralized_on"] >= report["attempts_neutralized_off"]
    assert report["neutralization_delta"] >= 1, (
        "ablation must exercise at least one adversarial injection the defense "
        f"catches and OFF misses; got {report}"
    )
    # OFF is the un-defended baseline: the injection attempt is not surfaced.
    assert report["attempts_neutralized_off"] == 0


def test_hallucination_rate_is_zero_both_arms_with_honest_note():
    # The deterministic engine cannot be manipulated by injected prose, so its
    # hallucination_rate is 0 in BOTH arms. The ablation states this honestly
    # rather than manufacturing a delta.
    report = run_injection_ablation(REPO_ROOT)
    assert report["hallucination_rate_on"] == 0.0
    assert report["hallucination_rate_off"] == 0.0
    assert (
        "note" in report and "deterministic" in report["note"].lower()
    ), "ablation must explain WHY the hallucination_rate delta is 0 here"


def test_ablation_does_not_mutate_the_scored_recall_path():
    # F1 GUARD: running the ablation (which toggles a benchmark-only defense skip)
    # must not perturb the recall harness. Run the F1 aggregate before and after;
    # it must be identical (the skip is local to the ablation runner).
    from tests.scenario_harness import aggregate, discover_scenarios, run_scenario

    def f1_snapshot():
        results = [run_scenario(e) for e in discover_scenarios(REPO_ROOT)]
        return aggregate(results)

    before = f1_snapshot()
    run_injection_ablation(REPO_ROOT)
    after = f1_snapshot()
    assert before["f1"] == after["f1"] == 1.0
    assert before == after, "ablation leaked state into the scored recall path"
