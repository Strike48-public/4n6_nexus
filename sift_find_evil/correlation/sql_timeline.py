"""SQL cross-artifact timeline correlation using stdlib sqlite3.

Loads a normalized list of timeline events into an in-memory SQLite table and
runs a time-windowed self-join to correlate activity across *different*
forensic sources (mft/evtx/pcap/registry/memory). Two events correlate when
they fall within ``window_seconds`` of each other, come from different sources,
and share either an actor or a target.

A CONTRADICTION is a special correlation: the SAME actor performing DIFFERENT
event types inside an overlapping window. Contradictions are NEVER auto-resolved
- they are surfaced with ``status='UNRESOLVED'`` for a downstream verifier
(human or LLM) to adjudicate.

Security posture: the built-in correlation uses only parameterized, static SQL.
Any user- or LLM-supplied rule string must pass :func:`validate_rule_string`,
which is reject-to-record (raises), never execute. duckdb/neo4j are not
available; this module is pure stdlib.
"""

from __future__ import annotations

import re
import sqlite3
from dataclasses import dataclass
from typing import Any, Dict, List

# Allow-list: rule strings may only contain these characters. Anything else
# (semicolons, quotes, parens beyond simple comparisons) is rejected outright.
_ALLOWED_RULE_CHARS = re.compile(r"^[A-Za-z0-9_.\s=<>!-]+$")

# Forbidden SQL/DDL keywords - reject-to-record if any appear (case-insensitive,
# word-boundary matched so "updated_actor" would not trip UPDATE spuriously via
# substring, but standalone DDL verbs are caught).
_FORBIDDEN_KEYWORDS = re.compile(
    r"\b(DROP|DELETE|UPDATE|INSERT|ATTACH|PRAGMA|ALTER|CREATE|EXEC|UNION|SELECT)\b",
    re.IGNORECASE,
)

# Default correlation window in seconds.
_DEFAULT_WINDOW_SECONDS = 5

# Columns expected on every event dict.
_EVENT_COLUMNS = ("ts", "source", "actor", "target", "type", "raw")


class RuleRejectedError(ValueError):
    """Raised when a user/LLM-supplied rule string fails the hard guard.

    The offending rule is recorded on the exception but is never executed.
    """

    def __init__(self, rule: str, reason: str) -> None:
        """Initialize with the rejected rule and a human-readable reason."""
        self.rule = rule
        self.reason = reason
        super().__init__(f"Rule rejected ({reason}): {rule!r}")


@dataclass(frozen=True)
class Correlation:
    """A correlated pair of cross-source timeline events.

    Attributes:
        a: The first event dict.
        b: The second event dict.
        relation: Why they correlate - "actor" (shared actor) or "target"
            (shared target).
    """

    a: Dict[str, Any]
    b: Dict[str, Any]
    relation: str


def validate_rule_string(rule: str) -> str:
    """Validate a user/LLM-supplied rule string against the hard guard.

    The rule must be a non-empty string, contain only allow-listed characters,
    and contain no forbidden SQL/DDL keywords. This function never executes the
    rule; it only accepts (returns it unchanged) or rejects (raises).

    Args:
        rule: The candidate rule string.

    Returns:
        The rule string unchanged if it passes both checks.

    Raises:
        RuleRejectedError: If the rule is empty, contains disallowed
            characters, or contains a forbidden keyword.
    """
    if not isinstance(rule, str) or not rule.strip():
        raise RuleRejectedError(str(rule), "empty or non-string")

    if not _ALLOWED_RULE_CHARS.match(rule):
        raise RuleRejectedError(rule, "disallowed characters")

    match = _FORBIDDEN_KEYWORDS.search(rule)
    if match:
        raise RuleRejectedError(rule, f"forbidden keyword: {match.group(0).upper()}")

    return rule


def _load_events(conn: sqlite3.Connection, events: List[Dict[str, Any]]) -> None:
    """Create the events table (indexed on ts, actor) and load rows.

    Uses only static DDL and parameterized inserts; event field values are
    always bound, never interpolated.
    """
    conn.execute(
        "CREATE TABLE events ("
        "rowid_ INTEGER PRIMARY KEY, "
        "ts TEXT, source TEXT, actor TEXT, target TEXT, type TEXT, raw TEXT)"
    )
    conn.execute("CREATE INDEX idx_events_ts_actor ON events(ts, actor)")

    rows = [
        (
            idx,
            event.get("ts"),
            event.get("source"),
            event.get("actor"),
            event.get("target"),
            event.get("type"),
            event.get("raw"),
        )
        for idx, event in enumerate(events)
    ]
    conn.executemany(
        "INSERT INTO events (rowid_, ts, source, actor, target, type, raw) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        rows,
    )


def correlate_timeline(
    events: List[Dict[str, Any]],
    window_seconds: int = _DEFAULT_WINDOW_SECONDS,
) -> List[Correlation]:
    """Correlate cross-source events within a time window.

    Loads events into an in-memory SQLite table and runs a parameterized,
    time-windowed self-join. Two events correlate when they are from different
    sources, fall within ``window_seconds``, and share an actor or a target.

    Args:
        events: Normalized event dicts with keys ts, source, actor, target,
            type, raw. Inputs are never mutated.
        window_seconds: Maximum absolute time gap (seconds) for a correlation.

    Returns:
        A list of :class:`Correlation` rows, deduplicated so each unordered
        pair appears once, ordered by (a.rowid, b.rowid).
    """
    if not events:
        return []

    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    try:
        _load_events(conn, events)
        query = (
            "SELECT "
            "e1.ts AS ts, e1.source AS source, e1.actor AS actor, "
            "e1.target AS target, e1.type AS type, e1.raw AS raw, "
            "e2.ts AS ts2, e2.source AS source2, e2.actor AS actor2, "
            "e2.target AS target2, e2.type AS type2, e2.raw AS raw2, "
            "CASE WHEN e1.actor = e2.actor THEN 'actor' ELSE 'target' END AS relation "
            "FROM events e1 "
            "JOIN events e2 ON e1.rowid_ < e2.rowid_ "
            "WHERE e1.source <> e2.source "
            "AND abs((julianday(e1.ts) - julianday(e2.ts)) * 86400) <= ? "
            "AND (e1.actor = e2.actor OR e1.target = e2.target) "
            "ORDER BY e1.rowid_, e2.rowid_"
        )
        cursor = conn.execute(query, (window_seconds,))
        correlations: List[Correlation] = []
        for row in cursor.fetchall():
            event_a = {col: row[col] for col in _EVENT_COLUMNS}
            event_b = {col: row[f"{col}2"] for col in _EVENT_COLUMNS}
            correlations.append(
                Correlation(a=event_a, b=event_b, relation=row["relation"])
            )
        return correlations
    finally:
        conn.close()


def find_contradictions(
    events: List[Dict[str, Any]],
    window_seconds: int = _DEFAULT_WINDOW_SECONDS,
) -> List[Dict[str, Any]]:
    """Surface UNRESOLVED contradictions across sources.

    A contradiction is the SAME actor with DIFFERENT event types across
    different sources within the overlapping window. These are never
    auto-resolved; each is tagged ``status='UNRESOLVED'`` so a downstream
    verifier can adjudicate.

    Args:
        events: Normalized event dicts (see :func:`correlate_timeline`).
        window_seconds: Maximum absolute time gap (seconds).

    Returns:
        A list of dicts, each describing one contradiction with keys: actor,
        type_a, type_b, source_a, source_b, ts_a, ts_b, status, and the raw
        event pair under a/b.
    """
    contradictions: List[Dict[str, Any]] = []
    for corr in correlate_timeline(events, window_seconds=window_seconds):
        same_actor = corr.a["actor"] is not None and corr.a["actor"] == corr.b["actor"]
        different_type = corr.a["type"] != corr.b["type"]
        if same_actor and different_type:
            contradictions.append(
                {
                    "actor": corr.a["actor"],
                    "type_a": corr.a["type"],
                    "type_b": corr.b["type"],
                    "source_a": corr.a["source"],
                    "source_b": corr.b["source"],
                    "ts_a": corr.a["ts"],
                    "ts_b": corr.b["ts"],
                    "a": corr.a,
                    "b": corr.b,
                    "status": "UNRESOLVED",
                }
            )
    return contradictions
