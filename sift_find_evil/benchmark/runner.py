"""Benchmark runner: grade agent outputs against the corpus (gallery idea #7).

Takes a mapping of case-name -> agent output ({"flagged": set, "asserted_absent":
set}) and scores it with the hallucination scorer. A case with NO output is
treated as silence (empty flags, empty abstentions) - so a missing answer is
never silently credited as either a correct flag or a proven negative.
"""

from __future__ import annotations

from .hallucination import BenchmarkCase, SuiteResult, score_suite


def run_benchmark(
    corpus: list[BenchmarkCase],
    outputs: dict[str, dict],
) -> SuiteResult:
    """Grade ``outputs`` against ``corpus`` and return the aggregate result.

    Args:
        corpus: The benchmark cases (ground truth).
        outputs: case-name -> {"flagged": iterable, "asserted_absent": iterable}.
            A case absent from ``outputs`` (or missing a key) is scored as
            silence, which the scorer never credits.

    Returns:
        A SuiteResult with the headline ``zero_false_confirmations`` gate.
    """
    triples = []
    for case in corpus:
        out = outputs.get(case.name, {})
        flagged = frozenset(out.get("flagged", ()))
        asserted_absent = frozenset(out.get("asserted_absent", ()))
        triples.append((case, flagged, asserted_absent))
    return score_suite(triples)
