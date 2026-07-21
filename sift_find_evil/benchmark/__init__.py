"""Hallucination / abstention benchmark for 4n6 Nexus.

Scores what recall/F1 cannot: resistance to over-calling (false-positive traps),
active abstention (proven negatives), and a defensible ``hallucination_rate``.
See ``hallucination`` for the scorer.
"""

from .hallucination import (
    BenchmarkCase,
    BenchmarkResult,
    SuiteResult,
    score_case,
    score_suite,
)

__all__ = [
    "BenchmarkCase",
    "BenchmarkResult",
    "SuiteResult",
    "score_case",
    "score_suite",
]
