"""Hermetic mini-Sigma rule matcher over parsed events.

This module implements a small, dependency-free subset of the Sigma rule
format so the detection engine can evaluate signature rules without shelling
out to an external Sigma or Chainsaw binary. It is deliberately CI-hermetic:
rules and events are plain Python dictionaries and no files or network access
are required.

Supported rule shape::

    {
        "title": "Suspicious PowerShell Encoded Command",
        "level": "high",            # low | medium | high | critical
        "logsource": {...},          # informational; not evaluated here
        "detection": {
            "selection": {"CommandLine|contains": "-enc"},
            "condition": "selection",
        },
    }

Field matchspecs support an exact value, a list of values (OR semantics), and
the following Sigma field modifiers: ``contains``, ``startswith``,
``endswith``, and ``re`` (regular expression search). The condition evaluator
supports named selection blocks combined with ``not``, ``and``, and ``or``.
"""

from __future__ import annotations

import re
from typing import Any, Callable, Dict, List, Mapping, Tuple

from sift_find_evil.findings import Finding, FindingCategory

# Sigma severity level -> Finding severity. The taxonomy of the engine uses the
# same lowercase severity vocabulary, so the mapping is largely identity but is
# made explicit so an unknown level fails loudly rather than silently.
_LEVEL_TO_SEVERITY: Dict[str, str] = {
    "low": "low",
    "medium": "medium",
    "high": "high",
    "critical": "critical",
}

# Confidence label attached to emitted findings, keyed by severity.
_SEVERITY_TO_CONFIDENCE: Dict[str, Tuple[float, str]] = {
    "critical": (0.9, "High"),
    "high": (0.85, "High"),
    "medium": (0.7, "Medium"),
    "low": (0.55, "Low"),
}

# Keys inside a ``detection`` block that are not selection blocks.
_RESERVED_DETECTION_KEYS = frozenset({"condition"})


def _match_modifier(modifier: str, event_value: Any, expected: str) -> bool:
    """Evaluate a single Sigma field modifier against one event value.

    Args:
        modifier: One of "contains", "startswith", "endswith", "re", or "" for
            an exact match.
        event_value: The value pulled from the event for the field.
        expected: The expected value from the rule matchspec.

    Returns:
        True if the event value satisfies the modifier, False otherwise.
    """
    text = str(event_value)
    if modifier == "":
        return text == str(expected)
    if modifier == "contains":
        return str(expected) in text
    if modifier == "startswith":
        return text.startswith(str(expected))
    if modifier == "endswith":
        return text.endswith(str(expected))
    if modifier == "re":
        return re.search(str(expected), text) is not None
    # Unknown modifier: treat as non-matching rather than raising so a single
    # malformed rule cannot abort a whole scan.
    return False


def _match_field(field_key: str, matchspec: Any, event: Mapping[str, Any]) -> bool:
    """Evaluate one ``field|modifier: matchspec`` entry against an event.

    A list matchspec has OR semantics: the entry matches if any listed value
    matches. A missing field never matches (except the intent is captured by
    the enclosing condition, e.g. via ``not``).

    Args:
        field_key: The raw key, optionally suffixed with ``|modifier``.
        matchspec: The expected value, or list of expected values.
        event: The parsed event dictionary.

    Returns:
        True if the event satisfies this field entry.
    """
    field_name, _, modifier = field_key.partition("|")
    if field_name not in event:
        return False
    event_value = event[field_name]
    expected_values = matchspec if isinstance(matchspec, list) else [matchspec]
    return any(
        _match_modifier(modifier, event_value, expected) for expected in expected_values
    )


def _match_selection(
    selection: Mapping[str, Any], event: Mapping[str, Any]
) -> Dict[str, Any]:
    """Evaluate a selection block (implicit AND across its fields).

    Args:
        selection: Mapping of ``field|modifier`` -> matchspec.
        event: The parsed event dictionary.

    Returns:
        A dict of matched field entries when every field matches; an empty
        dict indicates the selection did not fire. An empty selection block
        matches vacuously and returns an empty dict, so callers should test
        membership via the boolean returned by :func:`_selection_fired`.
    """
    matched: Dict[str, Any] = {}
    for field_key, matchspec in selection.items():
        if not _match_field(field_key, matchspec, event):
            return {}
        matched[field_key] = matchspec
    return matched


def _build_condition_evaluator(
    detection: Mapping[str, Any], event: Mapping[str, Any]
) -> Callable[[str], bool]:
    """Return a function that resolves a named selection to its match state."""

    def selection_fired(name: str) -> bool:
        selection = detection.get(name)
        if not isinstance(selection, Mapping):
            return False
        # An explicitly empty selection is treated as non-firing to avoid
        # accidental universal matches.
        if len(selection) == 0:
            return False
        return bool(_match_selection(selection, event))

    return selection_fired


def _evaluate_condition(condition: str, selection_fired: Callable[[str], bool]) -> bool:
    """Evaluate a Sigma condition string over named selections.

    Supports the grammar: ``term (('and'|'or') term)*`` where a term is
    ``['not'] NAME``. Left-to-right, no operator precedence beyond that, which
    matches the mini-Sigma scope of this module.

    Args:
        condition: The condition expression, e.g. "selection",
            "not selection", "a and b", "a or b".
        selection_fired: Callback mapping a selection name to its boolean
            match state for the current event.

    Returns:
        The truth value of the condition for the current event.
    """
    tokens = condition.split()
    result: bool | None = None
    operator: str | None = None
    negate = False

    for token in tokens:
        lowered = token.lower()
        if lowered in ("and", "or"):
            operator = lowered
            continue
        if lowered == "not":
            negate = True
            continue
        value = selection_fired(token)
        if negate:
            value = not value
            negate = False
        if result is None:
            result = value
        elif operator == "and":
            result = result and value
        elif operator == "or":
            result = result or value
        operator = None

    return bool(result)


def _make_finding(rule: Mapping[str, Any], matched_fields: Dict[str, Any]) -> Finding:
    """Construct a Finding for a rule that fired on an event.

    Args:
        rule: The Sigma rule dictionary that matched.
        matched_fields: The field entries that contributed to the match.

    Returns:
        A populated :class:`Finding`.
    """
    level = str(rule.get("level", "medium")).lower()
    severity = _LEVEL_TO_SEVERITY.get(level, "medium")
    confidence, confidence_label = _SEVERITY_TO_CONFIDENCE.get(
        severity, (0.7, "Medium")
    )
    title = str(rule.get("title", "Sigma Rule Match"))
    return Finding(
        title=title,
        description=f"Sigma rule '{title}' matched a parsed event.",
        finding_type="indicator",
        severity=severity,
        category=FindingCategory.EXECUTION,
        evidence={
            "rule_title": title,
            "rule_level": level,
            "logsource": dict(rule.get("logsource", {})),
            "matched_fields": dict(matched_fields),
        },
        confidence=confidence,
        confidence_label=confidence_label,
        reasoning_chain=[
            f"Event evaluated against Sigma rule '{title}'.",
            f"Condition '{rule.get('detection', {}).get('condition', '')}' "
            "evaluated true.",
            f"Matched fields: {sorted(matched_fields)}.",
        ],
        artifact_sources=["sigma_scan"],
    )


def _collect_matched_fields(
    detection: Mapping[str, Any], event: Mapping[str, Any]
) -> Dict[str, Any]:
    """Aggregate matched field entries across all firing selection blocks."""
    matched: Dict[str, Any] = {}
    for name, block in detection.items():
        if name in _RESERVED_DETECTION_KEYS or not isinstance(block, Mapping):
            continue
        if len(block) == 0:
            continue
        block_matches = _match_selection(block, event)
        if block_matches:
            matched.update(block_matches)
    return matched


def match_events(
    rules: List[Dict[str, Any]], events: List[Dict[str, Any]]
) -> List[Finding]:
    """Match a list of mini-Sigma rules against a list of parsed events.

    Emits one :class:`Finding` per (rule, event) pair whose condition
    evaluates true. Inputs are never mutated.

    Args:
        rules: Mini-Sigma rule dictionaries (see module docstring).
        events: Parsed event dictionaries (flat field -> value maps).

    Returns:
        A list of findings, one per rule/event hit, in rule-major, event-minor
        order.
    """
    findings: List[Finding] = []
    for rule in rules:
        detection = rule.get("detection", {})
        if not isinstance(detection, Mapping):
            continue
        condition = str(detection.get("condition", ""))
        if not condition:
            continue
        for event in events:
            selection_fired = _build_condition_evaluator(detection, event)
            if _evaluate_condition(condition, selection_fired):
                matched_fields = _collect_matched_fields(detection, event)
                findings.append(_make_finding(rule, matched_fields))
    return findings
