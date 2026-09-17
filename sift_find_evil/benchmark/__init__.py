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
from .heldout import (
    detector_logic_hash,
    discover_heldout,
    score_engine_over_heldout,
)
from .ablation import run_injection_ablation
from .red_team import (
    IterationScore,
    PlantedScenario,
    RedTeamObservation,
    RedTeamReport,
    run_red_team,
    score_iteration,
)

__all__ = [
    "BenchmarkCase",
    "BenchmarkResult",
    "SuiteResult",
    "score_case",
    "score_suite",
    "detector_logic_hash",
    "discover_heldout",
    "score_engine_over_heldout",
    "run_injection_ablation",
    "IterationScore",
    "PlantedScenario",
    "RedTeamObservation",
    "RedTeamReport",
    "run_red_team",
    "score_iteration",
]
