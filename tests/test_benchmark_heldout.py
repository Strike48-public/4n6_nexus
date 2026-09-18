"""Blind held-out hallucination benchmark (SFE-i7l7, benchmark 4->5).

The existing benchmark scores real engine output over the 16 recall scenarios -
the same scenarios the detectors were authored against, which the field's leaders
call a by-construction number. This adds a HELD-OUT corpus: scenario fixtures the
detectors were NOT tuned against, run through the REAL engine and scored blind.

Two honesty guards make the "held-out" claim defensible rather than marketing:
  1. The held-out fixtures live under scenarios/heldout/ and are EXCLUDED from the
     F1 recall harness (discover_scenarios skips them), so they cannot inflate F1
     and F1 cannot inflate them - the two corpora are disjoint.
  2. A detector-logic hash (digest over the detector source) is recorded with the
     result, so a later "teach to the test" detector edit is visible in the diff.

This is a hand-authored held-out set (not a third-party corpus); "held-out" means
"the detectors were not authored against these cases", not "independently sourced".
"""

from __future__ import annotations

from pathlib import Path

import pytest

from sift_find_evil.benchmark.heldout import (
    detector_logic_hash,
    discover_heldout,
    score_engine_over_heldout,
)
from sift_find_evil.benchmark.hallucination import SuiteResult

REPO_ROOT = Path(__file__).resolve().parents[1]

# The held-out corpus is deliberately NOT shipped to the Community-tier mirror
# (blind benchmark data must not be public; private-repo decision 2026-09-18).
# When the corpus is absent the whole module skips honestly instead of failing
# collection; in the private repo, where the corpus lives, every gate below
# runs for real.
_HELDOUT_CASES = discover_heldout(REPO_ROOT)
pytestmark = pytest.mark.skipif(
    len(_HELDOUT_CASES) < 3,
    reason=(
        "held-out corpus withheld from the Community tier (blind benchmark "
        "data stays private); this gate runs in the private repo"
    ),
)


def test_heldout_corpus_exists_and_is_discoverable():
    cases = discover_heldout(REPO_ROOT)
    assert len(cases) >= 3, (
        f"held-out corpus must have >=3 cases the detectors were not authored "
        f"against; found {len(cases)}"
    )
    # Each held-out scenario carries a real fixture directory the engine can run.
    for exp in cases:
        assert exp.directory.is_dir()


def test_heldout_is_excluded_from_the_f1_recall_harness():
    # The F1 harness must NOT see the held-out scenarios (else F1 and the held-out
    # score contaminate each other). discover_scenarios skips scenarios/heldout/.
    from tests.scenario_harness import discover_scenarios

    recall = discover_scenarios(REPO_ROOT)
    recall_dirs = {e.directory for e in recall}
    heldout_dirs = {e.directory for e in discover_heldout(REPO_ROOT)}
    assert heldout_dirs, "expected a held-out corpus"
    assert recall_dirs.isdisjoint(
        heldout_dirs
    ), "held-out scenarios leaked into the F1 recall harness"


def test_engine_scored_over_heldout_returns_a_suite_and_detector_hash():
    suite, det_hash = score_engine_over_heldout(REPO_ROOT)
    assert isinstance(suite, SuiteResult)
    assert suite.total_cases >= 3
    # A hallucination_rate is published for the held-out set (the headline metric).
    assert 0.0 <= suite.mean_hallucination_rate <= 1.0
    # Anti-overfit: a stable, non-empty detector-logic hash is recorded.
    assert isinstance(det_hash, str) and len(det_hash) == 64  # sha256 hexdigest


def test_detector_logic_hash_is_deterministic_and_content_bound():
    h1 = detector_logic_hash(REPO_ROOT)
    h2 = detector_logic_hash(REPO_ROOT)
    assert h1 == h2, "detector-logic hash must be deterministic for a given tree"
    assert len(h1) == 64


def test_heldout_suite_publishes_named_fp_fn_accounting():
    # Named FP/FN accounting SEPARATE from F1: every case exposes its own
    # false_positives / false_negatives artifact sets, serialized for the report.
    suite, _ = score_engine_over_heldout(REPO_ROOT)
    d = suite.to_dict()
    assert "per_case" in d and d["per_case"]
    for case in d["per_case"]:
        assert "false_positives" in case
        assert "false_negatives" in case
        assert isinstance(case["false_positives"], list)
        assert isinstance(case["false_negatives"], list)


def test_heldout_engine_does_not_overcall_the_planted_decoys():
    # The held-out cases plant loud-but-benign decoys; a court-defensible engine
    # must not flag them. If the engine trips a trap here, this surfaces it as a
    # real finding (not a silent pass) - that is the point of a held-out set.
    suite, _ = score_engine_over_heldout(REPO_ROOT)
    offenders = [c.name for c in suite.per_case if c.trap_hits or c.false_positives]
    assert not offenders, (
        f"engine over-called on held-out cases (flagged benign/decoy artifacts): "
        f"{offenders}"
    )


def test_heldout_engine_detects_the_planted_malicious_cases():
    # RECALL guard: zero_false_confirmations measures OVER-calling only - a null
    # engine that detects NOTHING trivially satisfies it. The held-out gate is only
    # load-bearing if it ALSO requires the planted malicious artifacts to be caught.
    # Every held-out case that declares malicious ground truth must be fully
    # recalled (no false negatives), or the set proves nothing about detection on
    # unseen actors. Mutation guard: a detector regression that misses a held-out
    # dropper drops this case's recall below 1.0 and fails here.
    suite, _ = score_engine_over_heldout(REPO_ROOT)
    missed = {
        c.name: sorted(c.false_negatives) for c in suite.per_case if c.false_negatives
    }
    assert (
        not missed
    ), f"engine missed planted held-out malicious artifacts (recall gap): {missed}"
    # At least one held-out case must actually carry a malicious detection, so the
    # recall assertion above is not vacuously true over an all-benign corpus.
    assert any(
        c.recall == 1.0 and c.total_flagged for c in suite.per_case
    ), "no held-out case exercised a real malicious detection"
