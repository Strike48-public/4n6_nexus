"""Self-attack corpus: the injection sanitizer is proven against a battery of
adversarial vectors (SFE-q715 slice 3).

VERDICT's injection-5 bar cites a "self-attack corpus" - an auditable set of
attack vectors the defense is run against, not scattered inline assertions. This
module IS that corpus consumer: it drives every vector in
``injection_defense.attack_corpus`` through the real sanitizer and asserts each
is detected AND neutralized, and that a clean control is left untouched.

The corpus is a static, deterministic, CI-safe data set (no live model, no
network). It is also load-bearing beyond tests: the benchmark injection ablation
folds it into the OFF/ON neutralization delta (see test_corpus_feeds_ablation).

RED-first: before slice 3 there is no ``injection_defense.attack_corpus``.
"""

from __future__ import annotations

import pytest

from sift_find_evil.injection_defense.attack_corpus import (
    ATTACK_CORPUS,
    AttackVector,
    clean_controls,
)
from sift_find_evil.injection_defense.sanitizer import (
    detect_injection,
    finding_from_scan,
    scan_and_wrap,
)


def test_corpus_is_nonempty_and_categorized():
    """The corpus must cover the named attack families, not a token sample."""
    assert len(ATTACK_CORPUS) >= 8, "corpus too thin to be a self-attack battery"
    categories = {v.category for v in ATTACK_CORPUS}
    # Every deterministic family VERDICT's injection-5 bar names must be present.
    for family in {"bidi", "homoglyph", "role-token", "forged-json", "sentinel-close"}:
        assert family in categories, f"corpus missing the {family} family"


@pytest.mark.parametrize("vector", ATTACK_CORPUS, ids=lambda v: v.name)
def test_every_attack_vector_is_detected(vector: AttackVector):
    """Each corpus vector must be surfaced as an injection attempt (not ingested)."""
    metas = detect_injection(vector.payload)
    assert metas, f"{vector.name}: attack not detected"
    fired = {str(m["type"]) for m in metas}
    assert (
        vector.expect_type in fired
    ), f"{vector.name}: expected indicator '{vector.expect_type}', got {sorted(fired)}"


@pytest.mark.parametrize("vector", ATTACK_CORPUS, ids=lambda v: v.name)
def test_every_attack_vector_is_neutralized_and_counts_only(vector: AttackVector):
    """Each vector must promote to a counts-only Finding, and its hostile marker
    must be neutralized in the artifact that actually reaches a downstream analyst.

    Which artifact depends on the family: BIDI/zero-width and role-token/confusable
    disguises are stripped/replaced in ``clean_text`` (steps 1-2); a sentinel-close
    BREAKOUT is defanged during wrapping, so it is neutralized in ``wrapped_text``
    (the raw close tag legitimately appears only as the sentinel boundary itself).
    """
    result = scan_and_wrap(vector.payload)
    finding = finding_from_scan(result)
    assert finding is not None, f"{vector.name}: no finding emitted"

    if vector.category == "sentinel-close":
        # The embedded close attempt is defanged in the wrapped output.
        assert (
            "[DEFANGED:sentinel-close]" in result.wrapped_text
        ), f"{vector.name}: sentinel-close attempt was not defanged"
    elif vector.category == "bidi":
        # Invisible/BIDI control codepoints are stripped from the cleaned text.
        assert (
            vector.hostile_marker not in result.clean_text
        ), f"{vector.name}: BIDI/zero-width control survived in clean_text"
    else:
        # Role-token / homoglyph / forged-JSON disguises are neutralized in place.
        assert (
            vector.hostile_marker not in result.clean_text
        ), f"{vector.name}: hostile marker survived in clean_text"
        assert (
            "[NEUTRALIZED:role-token]" in result.clean_text
        ), f"{vector.name}: no neutralization marker in clean_text"

    # Counts-only: the raw payload never rides inside the finding.
    assert vector.payload not in repr(
        finding.to_dict()
    ), f"{vector.name}: raw payload leaked into the finding"


@pytest.mark.parametrize("control", clean_controls(), ids=lambda c: c[:24])
def test_clean_controls_are_not_flagged(control: str):
    """Benign controls (including legitimate non-Latin evidence) must NOT trip the
    defense - the corpus proves specificity, not just recall."""
    assert (
        detect_injection(control) == []
    ), f"false positive on benign control: {control!r}"
    assert scan_and_wrap(control).clean_text == control


def test_corpus_feeds_ablation():
    """The corpus is load-bearing, not a dead artifact: the benchmark injection
    ablation neutralizes every hostile corpus vector in the ON arm and none in the
    OFF arm (a real neutralization delta over the whole battery)."""
    from sift_find_evil.benchmark.ablation import run_corpus_ablation

    report = run_corpus_ablation()
    assert report["corpus_vectors"] == len(ATTACK_CORPUS)
    assert report["attempts_neutralized_on"] == len(ATTACK_CORPUS)
    assert report["attempts_neutralized_off"] == 0
    assert report["neutralization_delta"] == len(ATTACK_CORPUS)
