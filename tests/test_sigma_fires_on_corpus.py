"""SFE-katy PR2: Sigma corpus FIRES on the real scored corpus, F1 intact.

The lesson repeated across SFE-1fkn (correlation) and the dead networkx graph:
a wired-and-unit-tested capability that produces ZERO output on the real 16
scenarios is a dead capability. This proves the Sigma path is load-bearing on the
scored corpus AND stays an F1-neutral overlay (Sigma findings carry no
`executable` key, so they never enter the named-executable tp/fp/fn accounting;
they are scored only via the opt-in `sigma_match` finding_counts category).
"""

from __future__ import annotations

from pathlib import Path

import tests.scenario_harness as h

_REPO_ROOT = Path(__file__).resolve().parent.parent


def _scenario(name: str) -> h.ScenarioExpectation:
    for expectation in h.discover_scenarios(_REPO_ROOT):
        if expectation.name == name:
            return expectation
    raise AssertionError(f"{name} scenario not found")


def test_ransomware_emits_sigma_findings() -> None:
    result = h.run_scenario(_scenario("02_ransomware"))
    sigma = [f for f in result.findings if "sigma_scan" in (f.artifact_sources or [])]
    titles = {f.title for f in sigma}
    assert (
        "Shadow Copy Deletion via vssadmin" in titles
    ), f"expected the vssadmin shadow-deletion Sigma rule to fire; saw {titles}"


def test_clean_baseline_emits_no_sigma_findings() -> None:
    # The F1-safety property: Sigma must NOT fire on the benign scenario, or the
    # named-executable-free sigma finding still trips the sigma_match FP branch.
    result = h.run_scenario(_scenario("01_clean_baseline"))
    sigma = [f for f in result.findings if "sigma_scan" in (f.artifact_sources or [])]
    assert sigma == [], f"Sigma must not fire on the clean baseline; saw {sigma}"


def test_sigma_is_load_bearing_across_corpus_and_f1_intact() -> None:
    results = [h.run_scenario(s) for s in h.discover_scenarios(_REPO_ROOT)]
    agg = h.aggregate(results)
    assert agg["sigma_matches"] >= 1, "Sigma produced zero output on the real corpus"
    assert agg["f1"] == 1.0
    assert agg["false_positives"] == 0 and agg["false_negatives"] == 0


def test_sigma_findings_carry_no_executable_key() -> None:
    # Structural guarantee that Sigma cannot perturb the executable-based scorer.
    for name in ("02_ransomware", "22_lateral_movement_logons"):
        result = h.run_scenario(_scenario(name))
        for f in result.findings:
            if "sigma_scan" in (f.artifact_sources or []):
                assert "executable" not in f.evidence
