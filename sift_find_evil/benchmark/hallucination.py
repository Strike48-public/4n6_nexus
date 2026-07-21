"""Hallucination / abstention scorer (gallery idea #7).

The scenario harness answers "did we find the evil" (recall/precision/F1) against
our own ground truth. The field's strongest entries (VERDICT, Council-SIFT,
GLASSBOX) argue that is a by-construction number and instead measure the harder
questions:

  * Over-calling: does the agent flag benign artifacts (``false_positive_traps``)
    it must NOT flag, or invent artifacts absent from ground truth entirely?
  * Abstention: does it ACTIVELY assert that a fact is absent
    (``negative_assertions``) when it is - credited only when actively proven,
    never for silence?

From these it derives a ``hallucination_rate`` = bad flags / total flags, a
number our F1 harness cannot produce. This module is a pure scorer over sets of
artifact identifiers; it is engine- and case-agnostic, so it can grade the
standalone orchestrator, the Claude Code path, or a replayed transcript.

Independently built by: MR. Robot Adversarial, OATH MCP, VERDICT, GLASSBOX,
SIFT-Bench, Council-SIFT.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class BenchmarkCase:
    """Ground truth for one benchmark case.

    ``malicious`` are artifacts that MUST be flagged (recall). ``false_positive_traps``
    are benign artifacts that must NOT be flagged (specificity). ``negative_assertions``
    are facts the agent must actively assert are absent (abstention).
    """

    name: str
    malicious: frozenset[str]
    false_positive_traps: frozenset[str] = field(default_factory=frozenset)
    negative_assertions: frozenset[str] = field(default_factory=frozenset)


@dataclass(frozen=True)
class BenchmarkResult:
    """Scored outcome for one case."""

    name: str
    recall: float
    trap_hits: int
    false_positives: frozenset[str]
    false_negatives: frozenset[str]
    negatives_proven: int
    negatives_missed: int
    hallucination_rate: float
    total_flagged: int

    def to_dict(self) -> dict:
        """Serialize for a results.jsonl drift log."""
        return {
            "name": self.name,
            "recall": round(self.recall, 4),
            "trap_hits": self.trap_hits,
            "false_positives": sorted(self.false_positives),
            "false_negatives": sorted(self.false_negatives),
            "negatives_proven": self.negatives_proven,
            "negatives_missed": self.negatives_missed,
            "hallucination_rate": round(self.hallucination_rate, 4),
            "total_flagged": self.total_flagged,
        }


@dataclass(frozen=True)
class SuiteResult:
    """Aggregated outcome across a benchmark suite."""

    total_cases: int
    mean_recall: float
    total_trap_hits: int
    total_false_positives: int
    mean_hallucination_rate: float
    negatives_proven: int
    negatives_missed: int
    zero_false_confirmations: bool
    per_case: list[BenchmarkResult]

    def to_dict(self) -> dict:
        return {
            "total_cases": self.total_cases,
            "mean_recall": round(self.mean_recall, 4),
            "total_trap_hits": self.total_trap_hits,
            "total_false_positives": self.total_false_positives,
            "mean_hallucination_rate": round(self.mean_hallucination_rate, 4),
            "negatives_proven": self.negatives_proven,
            "negatives_missed": self.negatives_missed,
            "zero_false_confirmations": self.zero_false_confirmations,
            "per_case": [r.to_dict() for r in self.per_case],
        }


def score_case(
    case: BenchmarkCase,
    flagged: frozenset[str],
    asserted_absent: frozenset[str],
) -> BenchmarkResult:
    """Score one case from what the agent flagged and what it asserted absent.

    Args:
        case: The ground truth.
        flagged: Artifact identifiers the agent flagged as malicious.
        asserted_absent: Facts the agent ACTIVELY asserted were absent.

    Returns:
        A BenchmarkResult with recall, trap hits, false positives, proven/missed
        negatives, and the derived hallucination_rate.
    """
    flagged = frozenset(flagged)
    asserted_absent = frozenset(asserted_absent)

    true_positives = flagged & case.malicious
    false_negatives = case.malicious - flagged
    recall = len(true_positives) / len(case.malicious) if case.malicious else 1.0

    # A trap hit = flagging a benign artifact we explicitly planted to catch
    # over-calling. A spurious false positive = flagging anything else that is
    # neither malicious nor a declared trap (an invented/decoy artifact).
    trap_hits_set = flagged & case.false_positive_traps
    false_positives = flagged - case.malicious - case.false_positive_traps

    # Abstention is credited only when ACTIVELY proven, never for silence.
    negatives_proven = len(case.negative_assertions & asserted_absent)
    negatives_missed = len(case.negative_assertions - asserted_absent)

    bad_flags = len(trap_hits_set) + len(false_positives)
    hallucination_rate = bad_flags / len(flagged) if flagged else 0.0

    return BenchmarkResult(
        name=case.name,
        recall=recall,
        trap_hits=len(trap_hits_set),
        false_positives=false_positives,
        false_negatives=false_negatives,
        negatives_proven=negatives_proven,
        negatives_missed=negatives_missed,
        hallucination_rate=hallucination_rate,
        total_flagged=len(flagged),
    )


def score_suite(
    cases: list[tuple[BenchmarkCase, frozenset[str], frozenset[str]]],
) -> SuiteResult:
    """Score a suite of (case, flagged, asserted_absent) triples.

    ``zero_false_confirmations`` is the headline OFF/ON gate: True only when no
    trap was tripped and no spurious artifact was flagged across the whole suite
    - the property a court-defensible agent must hold.
    """
    results = [score_case(c, flagged, absent) for c, flagged, absent in cases]
    n = len(results)
    total_trap_hits = sum(r.trap_hits for r in results)
    total_fp = sum(len(r.false_positives) for r in results)
    return SuiteResult(
        total_cases=n,
        mean_recall=(sum(r.recall for r in results) / n) if n else 1.0,
        total_trap_hits=total_trap_hits,
        total_false_positives=total_fp,
        mean_hallucination_rate=(
            sum(r.hallucination_rate for r in results) / n if n else 0.0
        ),
        negatives_proven=sum(r.negatives_proven for r in results),
        negatives_missed=sum(r.negatives_missed for r in results),
        zero_false_confirmations=(total_trap_hits == 0 and total_fp == 0),
        per_case=results,
    )
