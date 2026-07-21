"""Tests for SQL cross-artifact timeline correlation (Idea #12).

Covers stdlib-sqlite3 time-windowed cross-source correlation, UNRESOLVED
contradiction surfacing, window boundary behavior, and the hard guard that
rejects (never executes) user/LLM-supplied rule strings.

Every positive assertion is paired with an inverse/negative control.
"""

from __future__ import annotations

import pytest

from sift_find_evil.correlation.sql_timeline import (
    Correlation,
    RuleRejectedError,
    correlate_timeline,
    find_contradictions,
    validate_rule_string,
)


def _event(
    ts: str, source: str, actor: str, target: str, etype: str, raw: str = ""
) -> dict:
    """Build a synthetic timeline event dict."""
    return {
        "ts": ts,
        "source": source,
        "actor": actor,
        "target": target,
        "type": etype,
        "raw": raw or f"{source}:{actor}:{etype}",
    }


def test_cross_source_same_actor_within_window_correlates() -> None:
    # Arrange: two events, different sources, same actor, 2s apart
    events = [
        _event("2026-07-20T10:00:00", "evtx", "svc.exe", "hostA", "process_start"),
        _event("2026-07-20T10:00:02", "pcap", "svc.exe", "10.0.0.5", "network_connect"),
    ]

    # Act
    correlations = correlate_timeline(events, window_seconds=5)

    # Assert
    assert len(correlations) == 1
    assert isinstance(correlations[0], Correlation)
    assert correlations[0].relation == "actor"


def test_cross_source_shared_target_within_window_correlates() -> None:
    # Arrange: different actors, shared target, different sources
    events = [
        _event("2026-07-20T10:00:00", "mft", "a.exe", "C:/secret.doc", "file_write"),
        _event("2026-07-20T10:00:01", "registry", "b.exe", "C:/secret.doc", "reg_set"),
    ]

    # Act
    correlations = correlate_timeline(events, window_seconds=5)

    # Assert
    assert len(correlations) == 1
    assert correlations[0].relation == "target"


def test_same_source_pair_does_not_correlate() -> None:
    # Inverse control: identical timing/actor but SAME source -> no correlation
    events = [
        _event("2026-07-20T10:00:00", "evtx", "svc.exe", "hostA", "process_start"),
        _event("2026-07-20T10:00:02", "evtx", "svc.exe", "10.0.0.5", "network_connect"),
    ]

    # Act
    correlations = correlate_timeline(events, window_seconds=5)

    # Assert
    assert correlations == []


def test_events_outside_window_do_not_correlate() -> None:
    # Inverse control: cross-source same actor but 60s apart, window 5s
    events = [
        _event("2026-07-20T10:00:00", "evtx", "svc.exe", "hostA", "process_start"),
        _event("2026-07-20T10:01:00", "pcap", "svc.exe", "10.0.0.5", "network_connect"),
    ]

    # Act
    correlations = correlate_timeline(events, window_seconds=5)

    # Assert
    assert correlations == []


def test_same_actor_different_type_overlap_surfaced_unresolved() -> None:
    # Arrange: same actor, overlapping window, DIFFERENT type across sources
    events = [
        _event("2026-07-20T10:00:00", "memory", "mal.exe", "hostA", "inject"),
        _event("2026-07-20T10:00:03", "evtx", "mal.exe", "hostA", "process_start"),
    ]

    # Act
    contradictions = find_contradictions(events, window_seconds=5)

    # Assert
    assert len(contradictions) == 1
    c = contradictions[0]
    assert c["status"] == "UNRESOLVED"
    assert c["actor"] == "mal.exe"
    assert {c["type_a"], c["type_b"]} == {"inject", "process_start"}


def test_same_actor_same_type_is_not_a_contradiction() -> None:
    # Inverse control: same actor + same type -> no contradiction surfaced
    events = [
        _event("2026-07-20T10:00:00", "memory", "mal.exe", "hostA", "process_start"),
        _event("2026-07-20T10:00:03", "evtx", "mal.exe", "hostA", "process_start"),
    ]

    # Act
    contradictions = find_contradictions(events, window_seconds=5)

    # Assert
    assert contradictions == []


def test_malicious_rule_string_is_rejected_not_executed() -> None:
    # Arrange: SQL injection style rule strings
    malicious = [
        "1=1; DROP TABLE events;--",
        "DELETE FROM events",
        "actor = x'; ATTACH DATABASE 'evil.db' AS e;--",
        "PRAGMA table_info(events)",
        "INSERT INTO events VALUES (1)",
    ]

    # Act / Assert: each rejected via exception, never run
    for rule in malicious:
        with pytest.raises(RuleRejectedError):
            validate_rule_string(rule)


def test_benign_rule_string_passes_validation() -> None:
    # Inverse control: a simple allow-listed rule passes
    # Act
    result = validate_rule_string("actor eq svc.exe")

    # Assert
    assert result == "actor eq svc.exe"


def test_empty_rule_string_is_rejected() -> None:
    # Covers the empty/non-string reject-to-record branch.
    with pytest.raises(RuleRejectedError):
        validate_rule_string("   ")


def test_empty_event_list_returns_no_correlations() -> None:
    # Inverse control: no events -> the short-circuit empty-result branch.
    assert correlate_timeline([]) == []
