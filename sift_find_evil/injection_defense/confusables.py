"""Confusable / homoglyph folding for Trojan-Source injection defense.

A prompt-injection payload can disguise a role/system control token with
Unicode look-alikes so it survives an ASCII-only matcher - e.g. Cyrillic
``ѕуѕtem:`` (U+0455 U+0443 U+0455 ...) renders as ``system:`` but is not the
ASCII string ``system:``. Folding maps a curated set of Cyrillic/Greek/
full-width confusables to their ASCII skeleton so the disguised token becomes
matchable.

Two hard design constraints, both to keep false positives at zero on genuine
non-Latin forensic evidence:

  * The map is CURATED and small - only characters that (a) look like an ASCII
    letter used in a control token and (b) are common Trojan-Source vectors. It
    is deliberately NOT the full Unicode confusables database, which would fold
    legitimate text far too aggressively.
  * Folding is used as a DETECTION lens, not a blanket rewrite: the caller folds
    to decide whether a disguised token is present, and only rewrites output
    where folding REVEALS a control token that the raw text did not contain.
    Benign Cyrillic/Greek evidence that forms no ASCII control token is left
    byte-for-byte untouched (see ``sanitizer.scan_and_wrap``).

Pure and deterministic: same input always yields the same output; inputs are
never mutated.
"""

from __future__ import annotations

# Curated confusable -> ASCII skeleton map. Each key is a single codepoint whose
# glyph closely resembles the mapped ASCII letter AND which appears in role/
# system control tokens. Kept intentionally small: every entry is a known
# Trojan-Source vector, NOT the whole Unicode confusables table (which would fold
# and thereby corrupt benign non-Latin evidence).
_CONFUSABLE_TO_ASCII: dict[str, str] = {
    # --- Cyrillic lowercase look-alikes ---
    "а": "a",  # U+0430
    "е": "e",  # U+0435
    "о": "o",  # U+043E
    "с": "c",  # U+0441
    "р": "p",  # U+0440
    "у": "y",  # U+0443
    "х": "x",  # U+0445
    "ѕ": "s",  # U+0455 Cyrillic dze
    "і": "i",  # U+0456 Cyrillic byelorussian-ukrainian i
    "ј": "j",  # U+0458 Cyrillic je
    "ԁ": "d",  # U+0501 Cyrillic komi de
    "һ": "h",  # U+04BB Cyrillic shha
    "ѵ": "v",  # U+0475 Cyrillic izhitsa
    # --- Armenian look-alikes ---
    "ո": "n",  # U+0578 Armenian vo
    "ս": "u",  # U+057D Armenian seh
    # --- Greek lowercase look-alikes ---
    "ο": "o",  # U+03BF Greek omicron
    "ρ": "p",  # U+03C1 Greek rho
    "α": "a",  # U+03B1 Greek alpha
    "ϲ": "c",  # U+03F2 Greek lunate sigma
    "ϳ": "j",  # U+03F3 Greek yot
    "ν": "v",  # U+03BD Greek nu
    # --- Fullwidth Latin (NFKC-style) look-alikes ---
    "ｍ": "m",  # U+FF4D fullwidth m
    "ｔ": "t",  # U+FF54 fullwidth t
    "ｓ": "s",  # U+FF53 fullwidth s
    "ｅ": "e",  # U+FF45 fullwidth e
}


def fold_confusables(text: str) -> str:
    """Fold curated confusable codepoints to their ASCII skeleton.

    Args:
        text: Input text (never mutated).

    Returns:
        ``text`` with each mapped confusable replaced by its ASCII look-alike.
        Characters not in the curated map pass through unchanged, so genuine
        non-Latin text that uses no control-token confusables is returned
        effectively unchanged.
    """
    if not text:
        return text
    return "".join(_CONFUSABLE_TO_ASCII.get(ch, ch) for ch in text)


def has_confusables(text: str) -> bool:
    """True iff ``text`` contains at least one curated confusable codepoint."""
    return any(ch in _CONFUSABLE_TO_ASCII for ch in text)
