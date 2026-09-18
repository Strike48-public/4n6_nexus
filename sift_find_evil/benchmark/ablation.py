"""Defenses OFF/ON ablation for the hallucination benchmark (SFE-i7l7 PR2).

The field's top entries publish an OFF/ON ablation: run the corpus with defenses
disabled vs enabled and report the defenses' marginal value. This runner ablates
the INJECTION defense - the defense with a scorable effect on this deterministic
engine - and reports its DETECTION + NEUTRALIZATION efficacy.

Why not a hallucination_rate delta (the honest caveat): the deterministic engine
does not obey injected prose, so its hallucination_rate is 0 whether the sanitizer
is ON or OFF. Forcing a hallucination_rate delta here would be a meaningless 0. The
sanitizer's real, measurable value is that adversarial evidence text is DETECTED
(surfaced as an injection_attempt finding) and NEUTRALIZED (role tokens stripped,
payload sentinel-wrapped) when ON, and passes through untouched when OFF. The
report leads with that neutralization delta and states the hallucination_rate=0
result plainly - it would become a live delta only on an LLM-analyst path that can
be manipulated by the injected text.

This runner is benchmark-only: it reads the scenarios' injection fixtures and
scores the sanitizer directly. It NEVER runs or mutates the F1 recall path, so it
cannot perturb F1=1.00.

The OFF arm is MODELED (a constant 0), not re-run: the sanitizer is isolated to
the harness's ``_run_injection_for_scenario`` step and never feeds detector
internals, so "defenses off" definitionally yields zero neutralized attempts -
removing the only call site cannot produce a detection. This holds ONLY while that
isolation holds; if the sanitizer were ever woven into detector inputs, the OFF
arm would need to actually run the engine with a disable flag to stay honest.
"""

from __future__ import annotations

import importlib
from pathlib import Path

from ..injection_defense import finding_from_scan, scan_and_wrap
from ..injection_defense.attack_corpus import ATTACK_CORPUS


def run_corpus_ablation() -> dict:
    """Score the injection defense OFF vs ON over the static self-attack corpus.

    Unlike :func:`run_injection_ablation` (which reads scenario fixtures from
    disk), this runs the in-repo, deterministic self-attack battery
    (``injection_defense.attack_corpus.ATTACK_CORPUS``), so the corpus is
    load-bearing rather than a test-only artifact. ON arm: the sanitizer runs and
    every hostile vector is neutralized-and-surfaced. OFF arm: no sanitizer, so
    nothing is neutralized. Deterministic (no disk, no network, no wall-clock).
    """
    neutralized_on = sum(
        1
        for v in ATTACK_CORPUS
        if finding_from_scan(scan_and_wrap(v.payload)) is not None
    )
    return {
        "corpus_vectors": len(ATTACK_CORPUS),
        "attempts_neutralized_on": neutralized_on,
        "attempts_neutralized_off": 0,
        "neutralization_delta": neutralized_on,
    }


def _load_harness():
    """Import the scenario harness lazily (it lives under tests/)."""
    return importlib.import_module("tests.scenario_harness")


def _injection_texts(repo_root: Path) -> list[str]:
    """Collect every scenario's raw injection-fixture text (recall corpus).

    These are the adversarial evidence payloads the sanitizer exists to defend
    against. Scenarios without an injection fixture contribute nothing.
    """
    harness = _load_harness()
    texts: list[str] = []
    for exp in harness.discover_scenarios(repo_root):
        fixture = getattr(exp, "injection_fixture", None)
        if not fixture:
            continue
        path = exp.directory / fixture
        if path.is_file():
            texts.append(path.read_text(encoding="utf-8", errors="ignore"))
    return texts


def run_injection_ablation(repo_root: Path) -> dict:
    """Score the injection defense OFF vs ON over the corpus's adversarial texts.

    ON arm: each injection text is scanned (``scan_and_wrap`` + ``finding_from_scan``)
    - a detected attempt is neutralized and surfaced. OFF arm: the text is ingested
    with no sanitizer, so no attempt is detected or neutralized (the un-defended
    baseline). Returns a report with both arms, the neutralization delta, and the
    (deterministically zero) hallucination_rate for each arm plus a note.
    """
    texts = _injection_texts(repo_root)

    # ON: the sanitizer runs. Count texts where an injection attempt is detected
    # (finding_from_scan returns a finding) - i.e. neutralized-and-surfaced.
    neutralized_on = sum(
        1 for t in texts if finding_from_scan(scan_and_wrap(t)) is not None
    )
    # OFF: no sanitizer in the loop. Nothing is detected or neutralized - the raw
    # payload would reach a downstream analyst untouched.
    neutralized_off = 0

    return {
        "corpus_injection_texts": len(texts),
        "attempts_neutralized_on": neutralized_on,
        "attempts_neutralized_off": neutralized_off,
        "neutralization_delta": neutralized_on - neutralized_off,
        # The deterministic engine cannot be manipulated by injected prose, so its
        # over-call (hallucination) rate is 0 in BOTH arms. Reported honestly.
        "hallucination_rate_on": 0.0,
        "hallucination_rate_off": 0.0,
        "note": (
            "hallucination_rate is 0 in both arms because the deterministic engine "
            "does not act on injected prose; the neutralization_delta is the "
            "meaningful signal. On an LLM-analyst path (which can be manipulated by "
            "the injected text), the OFF arm's hallucination_rate would rise and the "
            "delta would become a live hallucination_rate reduction."
        ),
    }
