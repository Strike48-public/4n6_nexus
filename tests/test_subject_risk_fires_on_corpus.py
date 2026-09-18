"""SFE-dkfr: subject risk scoring FIRES and DISCRIMINATES on the real corpus.

The anti-dead-capability guard (the lesson the SFE-1fkn correlation revert
taught): a capability wired into the shared hardening path and unit-tested can
still be worthless if it produces nothing -- or produces the SAME output for
every scenario -- on the real recall corpus. These tests prove the risk overlay
is load-bearing end to end:

  * the clean baseline scores NO subject (nothing to be at risk about);
  * incident scenarios raise real banded subjects;
  * the overlay DISCRIMINATES (more than one band appears across the corpus),
    not a uniform verdict that carries no signal.

Honest note on CRITICAL scarcity, verified against the corpus (2026-07-26): no
scenario currently yields a CRITICAL subject, and that is CORRECT, not a bug. The
CRITICAL band is gated behind >=2 DISTINCT artifact sources on one subject. The
richest scenario (12_memory_intrusion) is memory-ONLY, so every subject is
legitimately single-source (caps at HIGH); the multi-source scenario
(03_timestomping, backdoor.exe across EventLog+MFT+Prefetch) carries a single
low-confidence timeline_tampering finding, which is a genuinely weak signal. So
the corpus has no subject that is BOTH strongly-evidenced AND multi-source -- a
property of the synthetic fixtures, not the scorer. F1 is unaffected throughout
(risk is additive HardeningReport metadata, never a scored finding).
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


def _all_results() -> list[h.ScenarioResult]:
    return [h.run_scenario(e) for e in h.discover_scenarios(_REPO_ROOT)]


# --- fires + discriminates on the real corpus ------------------------------


def test_clean_baseline_scores_no_subject() -> None:
    result = h.run_scenario(_scenario("01_clean_baseline"))
    assert result.hardening.subject_risk == [], (
        "a clean baseline must raise no at-risk subject; a nonempty list here "
        "means the overlay invents risk from benign activity"
    )


def test_incident_scenarios_raise_banded_subjects() -> None:
    result = h.run_scenario(_scenario("12_memory_intrusion"))
    assert (
        result.hardening.subject_risk
    ), "the memory-intrusion scenario must raise at least one risk subject"
    top = result.hardening.subject_risk[0]
    assert top["band"] in {
        "critical",
        "high",
        "medium",
    }, f"a real incident's top subject should not be LOW; got {top['band']}"


def test_risk_overlay_discriminates_across_the_corpus() -> None:
    # More than one distinct band must appear across the corpus; a single uniform
    # band (everything HIGH, or everything LOW) would carry no signal.
    bands = set()
    for r in _all_results():
        for subject in r.hardening.subject_risk:
            bands.add(subject["band"])
    assert (
        len(bands) >= 2
    ), f"risk overlay must discriminate across scenarios; saw only bands {bands}"


def test_f1_is_unaffected_by_the_risk_overlay() -> None:
    # The overlay must not add/drop a scored finding on any scenario.
    for r in _all_results():
        assert len(r.false_positives) == 0, f"{r.name}: unexpected FP"
        assert len(r.false_negatives) == 0, f"{r.name}: unexpected FN"
