"""Move C: real false-positive traps make the benchmark prove SPECIFICITY.

The skeptic's benchmark objection: with empty FP-traps, zero_false_confirmations
was mathematically identical to the engine's already-known zero-FP F1 - it proved
no independent specificity. This adds real trap artifacts: benign executables that
are PRESENT in a scenario's evidence but must NOT be flagged. Now the gate proves
the engine actively resists calling a benign-but-present artifact evil - a signal
distinct from recall.
"""

from pathlib import Path

from sift_find_evil.benchmark.engine_harness import (
    scenario_to_case,
    score_engine_over_scenarios,
)
from tests.scenario_harness import discover_scenarios, run_scenario

REPO_ROOT = Path(__file__).resolve().parents[1]


def _by_name(name):
    exp = next(e for e in discover_scenarios(REPO_ROOT) if e.name == name)
    return exp, run_scenario(exp)


def test_manifest_declared_traps_are_parsed():
    exp, _ = _by_name("02_ransomware")
    # The manifest now declares benign-but-present executables as FP traps.
    assert "cmd.exe" in exp.false_positive_traps


def test_traps_flow_into_the_benchmark_case():
    exp, result = _by_name("02_ransomware")
    case, _flagged = scenario_to_case(exp, result)
    assert "cmd.exe" in case.false_positive_traps
    # A trap must not also be in the malicious set (that would be contradictory).
    assert not (case.false_positive_traps & case.malicious)


def test_engine_resists_the_traps_zero_confirmations_holds():
    # The engine must NOT flag the benign trap -> still zero false confirmations,
    # but now that is a REAL specificity result (a trap was present to trip).
    suite = score_engine_over_scenarios(REPO_ROOT)
    assert suite.total_trap_hits == 0
    assert suite.zero_false_confirmations is True


def test_benchmark_now_has_nonzero_traps_to_prove_specificity():
    # Guards against the "empty traps = tautology" regression: at least one
    # scenario must contribute real traps, or the gate proves nothing new.
    total_traps = sum(
        len(scenario_to_case(exp, run_scenario(exp))[0].false_positive_traps)
        for exp in discover_scenarios(REPO_ROOT)
    )
    assert total_traps >= 1
