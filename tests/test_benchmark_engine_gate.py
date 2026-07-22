"""Benchmark scores REAL engine output and gates CI (move #2).

The skeptic's objection: the hallucination scorer existed but had never scored a
byte of engine output and was not a CI gate. This wires the scorer to the actual
recall harness - it maps each scenario's real detected-vs-expected output into a
BenchmarkCase (benign artifacts the engine saw but must not flag become
false-positive traps) and scores it. The headline gate is zero_false_confirmations
over the whole suite, asserted here so CI fails on any over-call.
"""

from pathlib import Path

from sift_find_evil.benchmark.engine_harness import (
    scenario_to_case,
    score_engine_over_scenarios,
)
from tests.scenario_harness import discover_scenarios, run_scenario

REPO_ROOT = Path(__file__).resolve().parents[1]


def test_scenario_to_case_maps_detected_and_expected():
    exp = next(e for e in discover_scenarios(REPO_ROOT) if e.name == "02_ransomware")
    result = run_scenario(exp)
    case, flagged = scenario_to_case(exp, result)
    # The malicious ground truth becomes the case's required detections.
    assert case.malicious == frozenset(exp.malicious_executables)
    # What the engine flagged is the detected set (lowercased executables).
    assert flagged == frozenset(n for n in result.detected_executables if n)


def test_engine_scores_zero_false_confirmations_across_suite():
    # The headline gate: the engine achieves F1=1.00 (0 FP), so scored through the
    # benchmark lens it must trip NO false-positive traps and invent nothing.
    suite = score_engine_over_scenarios(REPO_ROOT)
    assert suite.total_cases >= 1
    assert suite.zero_false_confirmations is True, (
        f"engine over-called: {suite.total_trap_hits} traps, "
        f"{suite.total_false_positives} spurious FPs"
    )
    assert suite.mean_hallucination_rate == 0.0


def test_clean_baseline_is_a_pure_fp_trap():
    # 01_clean_baseline has no malicious executables; anything flagged there is a
    # hallucination. The engine must flag nothing.
    exp = next(
        e for e in discover_scenarios(REPO_ROOT) if e.name == "01_clean_baseline"
    )
    result = run_scenario(exp)
    case, flagged = scenario_to_case(exp, result)
    assert case.malicious == frozenset()
    assert flagged == frozenset(), f"clean baseline over-called: {flagged}"


def test_suite_result_is_reportable():
    suite = score_engine_over_scenarios(REPO_ROOT)
    d = suite.to_dict()
    assert "mean_hallucination_rate" in d
    assert d["zero_false_confirmations"] is True
