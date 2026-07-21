"""Tests for the benchmark corpus + runner (gallery idea #7, data + entrypoint).

The scorer (test_hallucination_benchmark.py) is engine-agnostic. This exercises
the shipped corpus of hallucination cases and the runner that grades a set of
agent outputs against it, producing the headline zero_false_confirmations gate
and a JSON drift record.
"""

import json

from sift_find_evil.benchmark.corpus import BENCHMARK_CORPUS, load_corpus
from sift_find_evil.benchmark.runner import run_benchmark


def test_corpus_has_traps_and_negative_assertions():
    corpus = load_corpus()
    assert len(corpus) >= 3
    # The whole point: at least some cases carry FP traps and negative assertions.
    assert any(c.false_positive_traps for c in corpus)
    assert any(c.negative_assertions for c in corpus)


def test_corpus_is_frozen_ground_truth():
    # The corpus constant and load_corpus() agree (isolated copy the agent
    # never mutates).
    assert len(BENCHMARK_CORPUS) == len(load_corpus())


def test_a_perfect_agent_scores_zero_false_confirmations():
    corpus = load_corpus()
    # Simulate a perfect agent: flags exactly the malicious set, trips no trap,
    # proves every required negative.
    outputs = {
        c.name: {
            "flagged": set(c.malicious),
            "asserted_absent": set(c.negative_assertions),
        }
        for c in corpus
    }
    suite = run_benchmark(corpus, outputs)
    assert suite.zero_false_confirmations is True
    assert suite.mean_hallucination_rate == 0.0
    assert suite.negatives_missed == 0


def test_an_overcalling_agent_is_caught():
    corpus = load_corpus()
    # Simulate an agent that flags every trap too (the failure the benchmark exists
    # to catch) and never abstains.
    outputs = {
        c.name: {
            "flagged": set(c.malicious) | set(c.false_positive_traps),
            "asserted_absent": set(),
        }
        for c in corpus
    }
    suite = run_benchmark(corpus, outputs)
    assert suite.zero_false_confirmations is False
    assert suite.total_trap_hits > 0


def test_missing_output_for_a_case_counts_as_silence():
    corpus = load_corpus()
    # An agent that produced NO output for any case: no flags (misses evil),
    # no abstentions (misses negatives) - silence is never credited.
    suite = run_benchmark(corpus, outputs={})
    assert suite.mean_recall < 1.0
    if any(c.negative_assertions for c in corpus):
        assert suite.negatives_missed > 0


def test_runner_output_is_json_serializable():
    corpus = load_corpus()
    outputs = {c.name: {"flagged": set(c.malicious)} for c in corpus}
    suite = run_benchmark(corpus, outputs)
    # Must round-trip through JSON for a CI drift artifact.
    text = json.dumps(suite.to_dict())
    assert json.loads(text)["total_cases"] == len(corpus)
