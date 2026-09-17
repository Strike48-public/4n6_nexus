"""High-volume event dedup (gallery idea #35, SFE-p0hi PR2).

Some Windows/Sysmon events arrive in the thousands with almost no per-row
information: a workstation logs a 4624 for the same (user, source-IP, logon-type)
on every SMB reconnect, and Sysmon logs an EID3 for every packet flight to the
same (image, dst-IP, dst-port). Feeding all of them to the beaconing / lateral
detectors bloats fixtures and double-counts one behaviour as many.

This module collapses such events to the FIRST occurrence per distinct tuple,
data-driven by :class:`DedupRule`s. A rule names an ``event_id`` and the ordered
tuple of row ``keys`` that define "the same event"; the first row per
``(event_id, tuple-of-key-values)`` is kept and later exact repeats are dropped.
Everything else passes through untouched:

  * a row whose event id has no rule is never collapsed;
  * a row missing any keyed field cannot form a complete tuple, so it passes
    through rather than collapsing against another incomplete row (a missing
    field is not evidence of sameness).

Pure and deterministic: same rows + rules always yield the same output in input
order, and neither the input list nor the row dicts are mutated.

Operators tune this without editing code via :func:`resolve_dedup_rules`, which
merges an optional case-config mapping over :data:`DEFAULT_RULES` (add a rule,
retune an existing event id's keys, or disable a default). The case layer owns
loading that mapping from ``CASE.yaml`` (see ``case/manager.py``); this module
takes the already-parsed dict so it stays I/O-free and unit-testable.

### Known blind spots (honest, by design)

  * **Time-blind.** Collapsing to first-occurrence discards later timestamps, so
    a burst and a slow drip of the same tuple look identical here. Beaconing
    cadence analysis must run on the pre-collapse stream (or a rule must add a
    coarse time bucket to its keys) - dedup is a de-bloat pass, not a timeline.
  * **Channel-scope.** Rules key on ``EventId`` alone; a caller mixing multiple
    log channels that reuse an id would need the channel in the tuple. The
    defaults target the Security (4624) and Sysmon (EID3) channels callers feed
    in separately today.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Optional


@dataclass(frozen=True)
class DedupRule:
    """A first-occurrence-per-tuple collapse rule for one event id.

    Attributes:
        event_id: The numeric Windows/Sysmon event id this rule applies to.
        keys: Ordered row-dict field names whose values define "the same event".
            A row missing any of these is treated as incomplete and never
            collapsed.
        label: Human-readable tag for the collapsed class (report/debug only).
    """

    event_id: int
    keys: tuple[str, ...]
    label: str


# Default rules for the two highest-volume, lowest-information event shapes we
# ingest. Keys use EvtxECmd / Sysmon column names as they arrive in parsed rows.
DEFAULT_RULES: tuple[DedupRule, ...] = (
    DedupRule(
        event_id=4624,
        keys=("TargetUserName", "IpAddress", "LogonType"),
        label="successful_logon",
    ),
    DedupRule(
        event_id=3,
        keys=("Image", "DestinationIp", "DestinationPort"),
        label="sysmon_network_connection",
    ),
)


def _event_id(row: dict) -> Optional[int]:
    """Return the row's integer event id, or None if absent/unparseable."""
    raw = row.get("EventId")
    if raw is None or raw == "":
        return None
    try:
        return int(raw)
    except (TypeError, ValueError):
        return None


def _tuple_key(row: dict, keys: tuple[str, ...]) -> Optional[tuple[str, ...]]:
    """Build the dedup tuple for ``row``, or None if any keyed field is empty.

    A missing/blank field yields None so the row is treated as incomplete and
    passes through uncollapsed - a missing field is not evidence of sameness.
    """
    values: list[str] = []
    for key in keys:
        value = row.get(key)
        if value is None:
            return None
        text = str(value).strip()
        if not text:
            return None
        values.append(text)
    return tuple(values)


def collapse_events(rows: Iterable[dict], rules: Iterable[DedupRule]) -> list[dict]:
    """Collapse high-volume rows to the first occurrence per rule tuple.

    Args:
        rows: Parsed event rows (dicts). Never mutated.
        rules: The dedup rules to apply; at most one rule per event id is
            expected, and when several share an event id the first is used.

    Returns:
        A new list preserving input order, containing the first row per
        ``(event_id, tuple)`` for ruled/complete rows and every unruled or
        incomplete row unchanged.
    """
    rules_by_id: dict[int, DedupRule] = {}
    for rule in rules:
        # First rule wins for a given id so a caller's dedupe of its own rule
        # list is deterministic.
        rules_by_id.setdefault(rule.event_id, rule)

    seen: set[tuple[int, tuple[str, ...]]] = set()
    out: list[dict] = []
    for row in rows:
        if not isinstance(row, dict):
            # Not a keyable row; pass through rather than aborting the pass on one
            # malformed element.
            out.append(row)
            continue
        event_id = _event_id(row)
        rule = rules_by_id.get(event_id) if event_id is not None else None
        if rule is None:
            out.append(row)
            continue

        key = _tuple_key(row, rule.keys)
        if key is None:
            # Incomplete tuple: cannot prove sameness, so never collapse.
            out.append(row)
            continue

        scoped = (event_id, key)
        if scoped in seen:
            continue
        seen.add(scoped)
        out.append(row)
    return out


def _as_list(value: Any) -> list:
    """Normalize an operator-config field to a list without raising.

    ``CASE.yaml`` is hand-authored, so a field meant to be a list is routinely a
    scalar (``disable: 4624``), a single mapping (``rules:`` with no ``-`` dash),
    or absent/empty. None becomes ``[]``; a list/tuple is returned as a list;
    anything else (scalar or a single ``{event_id: ...}`` mapping) becomes a
    one-element list so it is processed instead of crashing or being silently
    iterated by key.
    """
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return list(value)
    return [value]


def _coerce_event_id(raw: Any) -> Optional[int]:
    """Coerce a config-supplied event id to int, or None if it isn't one.

    Accepts an int, a float that is a whole number (``4624.0``), or a digit
    string (``"4624"``). Rejects ``bool`` (``True`` is not event id 1) and any
    non-numeric shape. Shared by the ``rules`` and ``disable`` paths so both
    coerce ids identically.
    """
    if isinstance(raw, bool):
        return None
    if isinstance(raw, int):
        return raw
    if isinstance(raw, float):
        return int(raw) if raw.is_integer() else None
    if isinstance(raw, str) and raw.strip().isdigit():
        return int(raw.strip())
    return None


def _coerce_rule(spec: Any) -> Optional[DedupRule]:
    """Build a :class:`DedupRule` from an operator config mapping, or None.

    A malformed entry (missing event_id/keys, empty keys, non-numeric id) is
    dropped rather than raising, so one bad rule in a case file never aborts the
    run.
    """
    if not isinstance(spec, dict):
        return None
    keys = spec.get("keys")
    if not isinstance(keys, (list, tuple)) or not keys:
        return None
    event_id = _coerce_event_id(spec.get("event_id"))
    if event_id is None:
        return None
    key_tuple = tuple(str(k) for k in keys)
    label = str(spec.get("label", f"event_{event_id}"))
    return DedupRule(event_id=event_id, keys=key_tuple, label=label)


def resolve_dedup_rules(overrides: Optional[dict]) -> tuple[DedupRule, ...]:
    """Merge operator overrides over :data:`DEFAULT_RULES`.

    The ``overrides`` mapping (already parsed from ``CASE.yaml`` by the case
    layer) supports:

      * ``rules``: a list of ``{event_id, keys, label}`` mappings. Each ADDS a
        rule; if its event id matches a default, it REPLACES that default's keys
        (retune without editing code). Malformed entries are ignored.
      * ``disable``: a list of event ids whose default rule is removed.

    Args:
        overrides: The case-config mapping, or ``None``/empty for defaults only.

    Returns:
        The resolved rule tuple. Returns :data:`DEFAULT_RULES` unchanged when
        there is nothing to override.
    """
    if not overrides:
        return DEFAULT_RULES

    disabled = {
        coerced
        for x in _as_list(overrides.get("disable"))
        if (coerced := _coerce_event_id(x)) is not None
    }
    # Keep insertion order: surviving defaults first, then operator additions,
    # with an operator rule replacing a default for the same id in place.
    resolved: dict[int, DedupRule] = {
        rule.event_id: rule for rule in DEFAULT_RULES if rule.event_id not in disabled
    }
    for spec in _as_list(overrides.get("rules")):
        rule = _coerce_rule(spec)
        if rule is not None and rule.event_id not in disabled:
            resolved[rule.event_id] = rule

    return tuple(resolved.values())
