"""Tests for the hallucination/abstention benchmark scorer (gallery idea #7).

The scenario harness measures recall/precision/F1 against our own ground truth.
That is a by-construction number the field's leaders (VERDICT, Council-SIFT)
would discount. This benchmark scores the harder questions: does the agent
resist calling benign artifacts evil (false-positive traps it must NOT flag),
does it actively assert facts are ABSENT when they are (negative assertions),
and it credits only ACTIVE retraction/absence, never silence. It yields a
defensible hallucination_rate our F1 harness cannot.

RED-first: sift_find_evil.benchmark did not exist before.
"""

from sift_find_evil.benchmark.hallucination import (
    BenchmarkCase,
    score_case,
    score_suite,
)


def _case(**kw) -> BenchmarkCase:
    base = dict(
        name="c",
        malicious=frozenset({"evil.exe"}),
        false_positive_traps=frozenset(),
        negative_assertions=frozenset(),
    )
    base.update(kw)
    return BenchmarkCase(**base)


def test_perfect_case_zero_hallucination():
    # Flags the real evil, trips no traps, asserts the required absence.
    case = _case(
        false_positive_traps=frozenset({"chrome_update.exe"}),
        negative_assertions=frozenset({"no_ transfer"}),
    )
    r = score_case(
        case,
        flagged=frozenset({"evil.exe"}),
        asserted_absent=frozenset({"no_ transfer"}),
    )
    assert r.hallucination_rate == 0.0
    assert r.recall == 1.0
    assert r.trap_hits == 0
    assert r.negatives_proven == 1


def test_tripping_a_false_positive_trap_raises_hallucination_rate():
    # Flagging a benign trap artifact is a hallucination.
    case = _case(false_positive_traps=frozenset({"chrome_update.exe"}))
    r = score_case(
        case,
        flagged=frozenset({"evil.exe", "chrome_update.exe"}),
        asserted_absent=frozenset(),
    )
    assert r.trap_hits == 1
    assert r.hallucination_rate > 0.0


def test_flagging_a_decoy_not_in_ground_truth_is_a_false_positive():
    # An artifact that is neither malicious nor a declared trap, flagged anyway.
    case = _case()
    r = score_case(
        case,
        flagged=frozenset({"evil.exe", "totally_made_up.exe"}),
        asserted_absent=frozenset(),
    )
    assert "totally_made_up.exe" in r.false_positives
    assert r.hallucination_rate > 0.0


def test_silence_is_not_credited_as_a_proven_negative():
    # A required negative assertion the agent never made -> not proven.
    case = _case(negative_assertions=frozenset({"no_c2_beacon"}))
    r = score_case(case, flagged=frozenset({"evil.exe"}), asserted_absent=frozenset())
    assert r.negatives_proven == 0
    assert r.negatives_missed == 1


def test_missing_the_real_evil_is_a_false_negative():
    case = _case()
    r = score_case(case, flagged=frozenset(), asserted_absent=frozenset())
    assert "evil.exe" in r.false_negatives
    assert r.recall == 0.0


def test_hallucination_rate_is_quarantined_over_findings_plus_quarantined():
    # hallucination_rate = (trap_hits + spurious FPs) / (flagged total)
    case = _case(false_positive_traps=frozenset({"benign.exe"}))
    r = score_case(
        case,
        flagged=frozenset({"evil.exe", "benign.exe", "spurious.exe"}),
        asserted_absent=frozenset(),
    )
    # 2 bad of 3 flagged
    assert r.trap_hits == 1
    assert "spurious.exe" in r.false_positives
    assert abs(r.hallucination_rate - (2 / 3)) < 1e-9


def test_suite_aggregates_and_gates():
    good = (_case(name="a"), frozenset({"evil.exe"}), frozenset())
    bad = (
        _case(name="b", false_positive_traps=frozenset({"benign.exe"})),
        frozenset({"evil.exe", "benign.exe"}),
        frozenset(),
    )
    suite = score_suite(
        [
            (good[0], good[1], good[2]),
            (bad[0], bad[1], bad[2]),
        ]
    )
    assert suite.total_cases == 2
    assert suite.mean_recall == 1.0  # both flagged the real evil
    assert suite.total_trap_hits == 1
    assert 0.0 < suite.mean_hallucination_rate < 1.0
    # The suite exposes an OFF/ON style pass gate: zero false-confirmations.
    assert suite.zero_false_confirmations is False  # one trap tripped
    # The suite serializes for a results.jsonl drift log.
    d = suite.to_dict()
    assert d["total_cases"] == 2
    assert d["total_trap_hits"] == 1
    assert len(d["per_case"]) == 2
    assert d["zero_false_confirmations"] is False


def test_clean_suite_reports_zero_false_confirmations():
    suite = score_suite(
        [
            (_case(name="a"), frozenset({"evil.exe"}), frozenset()),
            (_case(name="b"), frozenset({"evil.exe"}), frozenset()),
        ]
    )
    assert suite.zero_false_confirmations is True
    assert suite.mean_hallucination_rate == 0.0


def test_result_serializes_to_dict():
    r = score_case(
        _case(), flagged=frozenset({"evil.exe"}), asserted_absent=frozenset()
    )
    d = r.to_dict()
    assert d["name"] == "c"
    assert "hallucination_rate" in d and "recall" in d
