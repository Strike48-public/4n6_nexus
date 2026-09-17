"""Blind held-out hallucination benchmark (SFE-i7l7, benchmark 4->5).

The engine benchmark (``engine_harness.py``) scores the 16 recall scenarios - the
same scenarios the detectors were authored against. The field's leaders call that
a by-construction number. This module scores a HELD-OUT corpus instead: scenario
fixtures the detectors were NOT tuned against, run through the REAL engine and
scored through the same hallucination/abstention lens.

Two guards keep the "held-out" claim honest rather than marketing:

  * **Disjointness.** Held-out fixtures live under ``scenarios/heldout/`` and are
    EXCLUDED from the F1 recall harness (``discover_scenarios`` skips them). A
    held-out case can neither inflate F1 nor be inflated by it.
  * **Anti-overfit.** :func:`detector_logic_hash` digests the detector source, and
    the score records it. A later "teach to the test" detector edit changes the
    hash, so overfitting to the held-out set is visible in review.

This is a hand-authored held-out set, NOT a third-party corpus. "Held-out" here
means "the detectors were not authored against these cases", not "independently
sourced" - stated plainly so the claim survives a hostile read.
"""

from __future__ import annotations

import hashlib
import importlib
from pathlib import Path
from typing import Any

from .engine_harness import scenario_to_case
from .hallucination import SuiteResult, score_suite

# Detector source whose logic the held-out set must not be tuned against. The
# hash over these trees is recorded with every held-out score, so an edit that
# "teaches to the test" is visible as a hash change in the diff.
_DETECTOR_SOURCE_DIRS = ("sift_find_evil/detectors", "sift_find_evil/self_correction")


def _load_harness():
    """Import the scenario harness lazily (it lives under tests/)."""
    return importlib.import_module("tests.scenario_harness")


def discover_heldout(repo_root: Path) -> list[Any]:
    """Discover the held-out scenarios under ``scenarios/heldout/``.

    Parses each ``scenarios/heldout/**/scenario.yaml`` with the SAME loader the
    recall harness uses (``expectation_from_manifest``), so held-out cases obey
    the identical fixture schema yet never enter the F1 harness (which skips the
    ``heldout`` path). Returns the ScenarioExpectation list, sorted by directory.
    """
    harness = _load_harness()
    heldout_root = repo_root / "scenarios" / "heldout"
    if not heldout_root.is_dir():
        return []
    expectations = []
    for manifest_path in sorted(heldout_root.glob("**/scenario.yaml")):
        if "_schemas" in manifest_path.parts:
            continue
        expectation = harness.expectation_from_manifest(manifest_path)
        if expectation is not None:
            expectations.append(expectation)
    return expectations


def detector_logic_hash(repo_root: Path) -> str:
    """SHA-256 over the detector + self-correction source (anti-overfit anchor).

    Deterministic: files are hashed in sorted relative-path order, each prefixed
    with its path, so the digest is bound to both content and layout. Recorded
    alongside a held-out score so a detector change that overfits to the held-out
    corpus is visible as a hash change in the diff.
    """
    digest = hashlib.sha256()
    paths: list[Path] = []
    for rel in _DETECTOR_SOURCE_DIRS:
        base = repo_root / rel
        if base.is_dir():
            paths.extend(base.glob("**/*.py"))
    for path in sorted(paths, key=lambda p: p.relative_to(repo_root).as_posix()):
        digest.update(path.relative_to(repo_root).as_posix().encode("utf-8"))
        digest.update(b"\x00")
        digest.update(path.read_bytes())
        digest.update(b"\x00")
    return digest.hexdigest()


def score_engine_over_heldout(repo_root: Path) -> tuple[SuiteResult, str]:
    """Run the real engine over the held-out corpus and score it blind.

    Mirrors ``score_engine_over_scenarios`` but over ``scenarios/heldout/``.
    Returns ``(SuiteResult, detector_logic_hash)`` - the hallucination score plus
    the anti-overfit anchor. F1 is untouched: this runs per-scenario engine
    execution over the disjoint held-out tree, never the recall harness aggregate.
    """
    harness = _load_harness()
    triples = []
    for exp in discover_heldout(repo_root):
        result = harness.run_scenario(exp)
        case, flagged = scenario_to_case(exp, result)
        # The recall harness does not emit proven-negatives, so abstention is not
        # credited (silence is never a proven negative) - the honest treatment.
        triples.append((case, flagged, frozenset()))
    return score_suite(triples), detector_logic_hash(repo_root)
