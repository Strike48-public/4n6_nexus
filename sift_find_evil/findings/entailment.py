"""Deterministic evidence re-derivation / entailment engine.

A non-LLM verifier that re-checks every value a finding *asserts* against the
raw parser output. Hallucinated values become structurally unconfirmable:

* Token-boundary matching (via regex lookaround) prevents a fabricated pid
  ``459`` from spuriously "matching" inside ``14592``, or ``cain`` inside
  ``mccain``.
* Identity-anchor kinds (hash, ipv4, ipv6) that are absent force retraction of
  the finding regardless of any other supported values.
* Corroborating kinds (generic, filename) that miss only downgrade support -
  they do not force retraction.

The engine is pure and deterministic: same inputs always yield the same report,
and it never mutates its inputs.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, List

if TYPE_CHECKING:
    from .finding import Finding

# Minimum length for a generic token to be eligible for a match. Shorter tokens
# match too much noise to be evidence of anything.
GENERIC_MIN_LENGTH = 4

# Kinds whose absence is an *identity* contradiction: if the parser output does
# not contain them, the finding is asserting an artifact that was never seen.
IDENTITY_ANCHOR_KINDS = frozenset({"hash", "ipv4", "ipv6"})

# Per-kind "continuation" character classes. A candidate match is only accepted
# if it is not preceded or followed by one of these characters, giving us a
# token boundary appropriate to the value kind.
_BOUNDARY_CLASSES = {
    "pid": r"0-9",
    "hash": r"0-9a-fA-F",
    "ipv4": r"0-9.",
    "ipv6": r"0-9a-fA-F:",
    "filename": r"A-Za-z0-9_",
    "generic": r"A-Za-z0-9_",
}

# Default boundary class for unknown kinds: treat as a generic word token.
_DEFAULT_BOUNDARY_CLASS = r"A-Za-z0-9_"


@dataclass(frozen=True)
class FieldCheck:
    """Result of re-deriving a single asserted value from observed text.

    Attributes:
        path: Dotted path identifying the asserted field (informational).
        expected: The value the finding claims was observed.
        kind: Value kind driving boundary and anchor semantics.
        observed: True if ``expected`` appears on a token boundary in the text.
        matched: True if the value is accepted as supporting evidence (observed
            and satisfying kind constraints such as the generic min length).
        retract: True if this is an absent identity anchor that invalidates the
            finding on its own.
    """

    path: str
    expected: str
    kind: str
    observed: bool
    matched: bool
    retract: bool


@dataclass(frozen=True)
class EntailmentReport:
    """Aggregate re-derivation result for a set of asserted values.

    Attributes:
        all_supported: True only if every asserted value matched.
        checks: Per-field re-derivation results.
    """

    all_supported: bool
    checks: List[FieldCheck] = field(default_factory=list)


def _boundary_class(kind: str) -> str:
    """Return the continuation character class for a value kind."""
    return _BOUNDARY_CLASSES.get(kind, _DEFAULT_BOUNDARY_CLASS)


def _appears_on_boundary(expected: str, kind: str, observed_text: str) -> bool:
    """Check whether ``expected`` appears on a token boundary in the text.

    Uses negative lookbehind/lookahead over the kind's continuation class so a
    value only counts when it is not embedded inside a larger token of the same
    character family.

    Args:
        expected: The literal value to search for.
        kind: Value kind selecting the boundary character class.
        observed_text: Raw parser output to search within.

    Returns:
        True if a token-boundary occurrence exists.
    """
    if not expected or not observed_text:
        return False

    cls = _boundary_class(kind)
    pattern = rf"(?<![{cls}]){re.escape(expected)}(?![{cls}])"
    return re.search(pattern, observed_text) is not None


def _check_value(asserted: dict, observed_text: str) -> FieldCheck:
    """Re-derive a single asserted value into a FieldCheck.

    Args:
        asserted: One asserted value mapping with path/expected/kind.
        observed_text: Raw parser output to verify against.

    Returns:
        A FieldCheck describing observation, acceptance, and retraction.
    """
    path = str(asserted.get("path", ""))
    expected = str(asserted.get("expected", ""))
    kind = str(asserted.get("kind", "generic"))

    observed = _appears_on_boundary(expected, kind, observed_text)

    matched = observed
    if kind == "generic" and len(expected) < GENERIC_MIN_LENGTH:
        matched = False

    retract = kind in IDENTITY_ANCHOR_KINDS and not matched

    return FieldCheck(
        path=path,
        expected=expected,
        kind=kind,
        observed=observed,
        matched=matched,
        retract=retract,
    )


def check_entailment(
    asserted_values: List[dict], observed_text: str
) -> EntailmentReport:
    """Re-derive every asserted value against raw observed text.

    Args:
        asserted_values: List of ``{"path", "expected", "kind"}`` mappings.
        observed_text: Raw parser output the finding claims to summarize.

    Returns:
        An EntailmentReport. ``all_supported`` is True only if every value
        matched; any absent identity anchor sets its ``retract`` flag.
    """
    checks = [_check_value(value, observed_text) for value in asserted_values]
    all_supported = all(check.matched for check in checks)
    return EntailmentReport(all_supported=all_supported, checks=checks)


def entail_finding(finding: "Finding", observed_text: str) -> EntailmentReport:
    """Re-derive a finding's asserted values from its evidence.

    Reads ``finding.evidence["asserted_values"]`` (a list of asserted-value
    mappings) and verifies each against ``observed_text``.

    Args:
        finding: The finding to verify. Not mutated.
        observed_text: Raw parser output to verify against.

    Returns:
        An EntailmentReport for the finding's asserted values.
    """
    asserted_values = finding.evidence.get("asserted_values", [])
    return check_entailment(list(asserted_values), observed_text)
