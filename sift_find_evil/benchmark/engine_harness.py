"""Bridge the hallucination benchmark to REAL engine output (move #2).

The hallucination scorer (``hallucination.py``) and corpus existed but had never
scored a byte of the engine's actual output. This bridges them: it maps each
recall scenario's real detected-vs-expected result into a ``BenchmarkCase`` and
scores the engine's flags through the abstention/over-call lens, producing a
suite-level ``zero_false_confirmations`` gate that CI asserts.

The mapping is honest and conservative:
- ``malicious`` = the scenario's ground-truth malicious executables (what the
  engine MUST flag).
- ``flagged`` = what the engine actually detected (lowercased executables).
- Every non-malicious executable the engine flagged is, by construction, a
  spurious false positive under the scorer - so an F1=1.00 (zero-FP) run scores
  ``zero_false_confirmations = True``. If detection ever regresses into an
  over-call, this gate fails independently of the recall F1 number.

Scenario discovery + execution are injected (the harness lives under ``tests/``),
so this module stays a dependency-free part of the package.
"""

from __future__ import annotations

import importlib
from pathlib import Path
from typing import Any

from .hallucination import BenchmarkCase, SuiteResult, score_suite


def scenario_to_case(expectation: Any, result: Any) -> tuple[BenchmarkCase, frozenset]:
    """Map one scenario expectation + result into a (BenchmarkCase, flagged) pair.

    Args:
        expectation: A ScenarioExpectation (has ``name`` + ``malicious_executables``).
        result: The ScenarioResult from running it (has ``detected_executables``).

    Returns:
        ``(case, flagged)`` where ``case.malicious`` is the ground truth and
        ``flagged`` is the engine's detected executables (empty strings dropped).
    """
    malicious = frozenset(str(m).lower() for m in expectation.malicious_executables)
    flagged = frozenset(n for n in result.detected_executables if n)
    # Benign-but-present artifacts the manifest declares as traps. Excluding any
    # that (defensively) overlap the malicious set keeps the case self-consistent.
    traps = (
        frozenset(getattr(expectation, "false_positive_traps", frozenset())) - malicious
    )
    case = BenchmarkCase(
        name=expectation.name,
        malicious=malicious,
        # Declared traps make the gate prove SPECIFICITY: the engine must resist
        # flagging a benign artifact that is actually present in the evidence.
        # (Anything flagged-and-not-malicious is already scored as a spurious FP;
        # declared traps add named, evidence-present benign artifacts on top.)
        false_positive_traps=traps,
        negative_assertions=frozenset(),
    )
    return case, flagged


def _load_harness():
    """Import the scenario harness lazily (it lives under tests/)."""
    return importlib.import_module("tests.scenario_harness")


def score_engine_over_scenarios(repo_root: Path) -> SuiteResult:
    """Run the recall harness and score the engine's real output for hallucination.

    Discovers every scenario, runs the engine, maps each result into a benchmark
    case, and scores the suite. The headline ``zero_false_confirmations`` is True
    iff the engine flagged nothing outside ground truth across all scenarios.
    """
    harness = _load_harness()
    scenarios = harness.discover_scenarios(repo_root)
    triples: list[tuple[BenchmarkCase, frozenset, frozenset]] = []
    for exp in scenarios:
        result = harness.run_scenario(exp)
        case, flagged = scenario_to_case(exp, result)
        # No abstention claims are asserted from the recall harness (it does not
        # emit proven-negatives), so asserted_absent is empty - the scorer never
        # credits silence, which is the honest treatment.
        triples.append((case, flagged, frozenset()))
    return score_suite(triples)
