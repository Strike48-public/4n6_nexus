"""Load a pinned Sigma YAML corpus into matcher-ready rule dicts (SFE-katy PR2).

The matcher (:mod:`.matcher`) evaluates rule DICTS; the committed corpus ships as
auditable Sigma YAML under ``rules/sigma/*.yaml`` (config-as-data, versioned in
git). This loader parses that corpus and, crucially, REJECTS-TO-RECORD any rule
that uses grammar outside the hermetic mini-Sigma subset - an aggregation
(``| count()``), an unknown field modifier, or a missing condition - rather than
shipping a rule that would silently never fire and give false confidence. It
never evaluates a rule; it only accepts (returns the dict) or rejects (raises).

Supported subset (must stay in lockstep with :mod:`.matcher`):
- Field modifiers: ``contains``, ``startswith``, ``endswith``, ``re``, exact.
- Condition grammar: named selections combined with ``and`` / ``or`` / ``not``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List

import yaml

# Field modifiers the matcher understands (empty string = exact match).
_SUPPORTED_MODIFIERS = frozenset({"", "contains", "startswith", "endswith", "re"})

# Tokens a supported condition may contain besides selection names.
_CONDITION_OPERATORS = frozenset({"and", "or", "not"})

# Keys inside ``detection`` that are not selection blocks.
_RESERVED_DETECTION_KEYS = frozenset({"condition"})


class RuleRejectedError(ValueError):
    """Raised when a rule uses grammar outside the mini-Sigma subset.

    The rule is recorded on the exception but never evaluated.
    """

    def __init__(self, source: str, reason: str) -> None:
        """Initialize with a short source label and a human-readable reason."""
        self.source = source
        self.reason = reason
        super().__init__(f"Sigma rule rejected ({reason}): {source}")


def _validate_modifiers(selection: Dict[str, Any], source: str) -> None:
    """Reject a selection block using a field modifier the matcher lacks."""
    for field_key in selection:
        _, _, modifier = str(field_key).partition("|")
        if modifier not in _SUPPORTED_MODIFIERS:
            raise RuleRejectedError(source, f"unsupported field modifier '|{modifier}'")


def _validate_condition(condition: str, source: str) -> None:
    """Reject a condition using grammar beyond named selections + and/or/not.

    Anything with an aggregation pipe (``| count``), parentheses, or the ``of``
    quantifier is outside the mini-Sigma evaluator and would silently misfire.
    """
    if "|" in condition or "(" in condition or ")" in condition:
        raise RuleRejectedError(source, f"unsupported condition grammar: {condition!r}")
    for token in condition.split():
        lowered = token.lower()
        if lowered in _CONDITION_OPERATORS:
            continue
        if lowered in ("1", "all", "any", "of", "them"):
            raise RuleRejectedError(source, f"unsupported condition token '{token}'")


def _validate_rule(rule: Any, source: str) -> Dict[str, Any]:
    """Validate one parsed rule against the supported subset; return it or raise."""
    if not isinstance(rule, dict):
        raise RuleRejectedError(source, "rule is not a mapping")
    detection = rule.get("detection")
    if not isinstance(detection, dict):
        raise RuleRejectedError(source, "missing or malformed 'detection' block")
    condition = detection.get("condition")
    if not isinstance(condition, str) or not condition.strip():
        raise RuleRejectedError(source, "missing 'condition'")
    _validate_condition(condition, source)
    for name, block in detection.items():
        if name in _RESERVED_DETECTION_KEYS:
            continue
        if isinstance(block, dict):
            _validate_modifiers(block, source)
    return rule


def load_rule_text(text: str, source: str = "<string>") -> Dict[str, Any]:
    """Parse and validate a single Sigma rule from YAML text.

    Args:
        text: One Sigma rule document as YAML.
        source: A label used in rejection messages (e.g. the file name).

    Returns:
        The rule as a matcher-ready dict.

    Raises:
        RuleRejectedError: If the YAML is malformed or the rule uses unsupported
            grammar (missing condition, aggregation, unknown modifier).
    """
    try:
        parsed = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise RuleRejectedError(source, f"malformed YAML: {exc}") from exc
    return _validate_rule(parsed, source)


def load_sigma_corpus(corpus_dir: Path) -> List[Dict[str, Any]]:
    """Load and validate every ``*.yaml`` rule under ``corpus_dir``.

    A missing directory is not an error (Sigma is opt-in): it yields no rules.
    Every present rule must validate, so a malformed committed rule fails loudly
    at load rather than silently never matching.

    Args:
        corpus_dir: Directory holding the pinned Sigma YAML corpus.

    Returns:
        Matcher-ready rule dicts, ordered by file name.

    Raises:
        RuleRejectedError: If any committed rule is malformed or unsupported.
    """
    if not corpus_dir.is_dir():
        return []
    rules: List[Dict[str, Any]] = []
    for path in sorted(corpus_dir.glob("*.yaml")):
        rules.append(load_rule_text(path.read_text(encoding="utf-8"), source=path.name))
    return rules
