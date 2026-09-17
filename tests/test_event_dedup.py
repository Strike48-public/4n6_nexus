"""Tests for high-volume event dedup (gallery idea #35, SFE-p0hi PR2).

High-volume / low-information events (4624 logons, Sysmon EID3 network
connections) are collapsed to the first occurrence per distinct tuple so the
downstream beaconing / lateral detectors see a distinct set, not thousands of
near-identical rows. Data-driven: rules are frozen and operator-overridable.

Each behavior has an inverse/negative control; mutation guards pin the
first-occurrence and per-tuple-key semantics.
"""

from __future__ import annotations

import copy

from sift_find_evil.parsers.dedup import (
    DEFAULT_RULES,
    DedupRule,
    collapse_events,
    resolve_dedup_rules,
)


def _logon(user: str, ip: str, logon_type: str, record: int) -> dict:
    """A minimal 4624 row (EvtxECmd-shaped keys the default rule keys on)."""
    return {
        "EventId": 4624,
        "TargetUserName": user,
        "IpAddress": ip,
        "LogonType": logon_type,
        "RecordId": record,
    }


def _eid3(image: str, dst_ip: str, dst_port: str, record: int) -> dict:
    """A minimal Sysmon EID3 network-connection row."""
    return {
        "EventId": 3,
        "Image": image,
        "DestinationIp": dst_ip,
        "DestinationPort": dst_port,
        "RecordId": record,
    }


# --- DedupRule / defaults --------------------------------------------------


def test_default_rules_cover_4624_and_sysmon_eid3() -> None:
    ids = {rule.event_id for rule in DEFAULT_RULES}
    assert 4624 in ids
    assert 3 in ids


def test_dedup_rule_is_frozen() -> None:
    rule = DedupRule(event_id=4624, keys=("TargetUserName",), label="logon")
    try:
        rule.event_id = 5  # type: ignore[misc]
    except Exception as exc:  # dataclass(frozen=True) raises FrozenInstanceError
        assert "cannot assign" in str(exc) or "FrozenInstance" in type(exc).__name__
    else:
        raise AssertionError("DedupRule must be immutable")


# --- collapse_events: 4624 -------------------------------------------------


def test_collapse_keeps_one_row_per_distinct_logon_tuple() -> None:
    rows = [
        _logon("alice", "10.0.0.5", "3", 1),
        _logon("alice", "10.0.0.5", "3", 2),  # exact dup tuple -> dropped
        _logon("alice", "10.0.0.5", "3", 3),  # exact dup tuple -> dropped
        _logon("bob", "10.0.0.5", "3", 4),  # different user -> kept
    ]
    out = collapse_events(rows, DEFAULT_RULES)
    assert [r["RecordId"] for r in out] == [1, 4]


def test_collapse_keeps_first_occurrence_not_last() -> None:
    rows = [
        _logon("alice", "10.0.0.5", "3", 10),
        _logon("alice", "10.0.0.5", "3", 11),
    ]
    out = collapse_events(rows, DEFAULT_RULES)
    assert [r["RecordId"] for r in out] == [10]


def test_collapse_distinguishes_on_every_key_in_the_tuple() -> None:
    # Same user + ip but different logon type is a DIFFERENT tuple -> both kept.
    rows = [
        _logon("alice", "10.0.0.5", "3", 1),
        _logon("alice", "10.0.0.5", "10", 2),
    ]
    out = collapse_events(rows, DEFAULT_RULES)
    assert [r["RecordId"] for r in out] == [1, 2]


# --- collapse_events: Sysmon EID3 ------------------------------------------


def test_collapse_sysmon_eid3_by_image_dst_ip_port() -> None:
    rows = [
        _eid3("evil.exe", "203.0.113.66", "443", 1),
        _eid3("evil.exe", "203.0.113.66", "443", 2),  # dup -> dropped
        _eid3("evil.exe", "203.0.113.66", "8080", 3),  # diff port -> kept
    ]
    out = collapse_events(rows, DEFAULT_RULES)
    assert [r["RecordId"] for r in out] == [1, 3]


# --- pass-through of unmatched / unkeyable rows ----------------------------


def test_rows_with_no_matching_rule_pass_through_untouched() -> None:
    # 4688 has no default dedup rule; every row is preserved regardless of dups.
    rows = [
        {"EventId": 4688, "NewProcessName": "a.exe", "RecordId": 1},
        {"EventId": 4688, "NewProcessName": "a.exe", "RecordId": 2},
    ]
    out = collapse_events(rows, DEFAULT_RULES)
    assert [r["RecordId"] for r in out] == [1, 2]


def test_rows_missing_a_keyed_field_are_never_collapsed() -> None:
    # A 4624 row missing a key field cannot form a complete tuple; it must pass
    # through rather than collapse against another incomplete row (a missing
    # field is not evidence of sameness).
    rows = [
        {"EventId": 4624, "TargetUserName": "alice", "RecordId": 1},  # no ip/type
        {"EventId": 4624, "TargetUserName": "alice", "RecordId": 2},
    ]
    out = collapse_events(rows, DEFAULT_RULES)
    assert [r["RecordId"] for r in out] == [1, 2]


def test_empty_and_none_field_values_are_treated_as_incomplete() -> None:
    rows = [
        _logon("alice", "", "3", 1),  # blank ip -> incomplete -> pass through
        _logon("alice", "", "3", 2),
    ]
    out = collapse_events(rows, DEFAULT_RULES)
    assert [r["RecordId"] for r in out] == [1, 2]


def test_collapse_empty_is_empty() -> None:
    assert collapse_events([], DEFAULT_RULES) == []


def test_collapse_does_not_mutate_input_rows_or_list() -> None:
    rows = [
        _logon("alice", "10.0.0.5", "3", 1),
        _logon("alice", "10.0.0.5", "3", 2),
        _eid3("evil.exe", "203.0.113.66", "443", 3),
    ]
    before = copy.deepcopy(rows)
    collapse_events(rows, DEFAULT_RULES)
    # Neither the list nor any row dict is touched (no _seen markers, no pops).
    assert rows == before


def test_collapse_passes_through_non_dict_rows() -> None:
    # A stray None/str/int row must not abort the whole pass with AttributeError.
    rows = [_logon("alice", "10.0.0.5", "3", 1), None, "garbage", 42]
    out = collapse_events(rows, DEFAULT_RULES)
    assert out == [_logon("alice", "10.0.0.5", "3", 1), None, "garbage", 42]


def test_collapse_first_rule_wins_for_duplicate_event_id() -> None:
    # Two rules for the same event id: the first supplied is used (documented).
    rules = (
        DedupRule(event_id=4624, keys=("TargetUserName",), label="by-user"),
        DedupRule(event_id=4624, keys=("IpAddress",), label="by-ip"),
    )
    rows = [
        _logon("alice", "10.0.0.5", "3", 1),
        _logon("alice", "10.0.0.99", "3", 2),  # same user, diff ip
    ]
    # Keyed by user only (first rule) -> second row collapses.
    out = collapse_events(rows, rules)
    assert [r["RecordId"] for r in out] == [1]


# --- resolve_dedup_rules: operator overrides -------------------------------


def test_resolve_returns_defaults_when_no_overrides() -> None:
    assert resolve_dedup_rules(None) == DEFAULT_RULES
    assert resolve_dedup_rules({}) == DEFAULT_RULES


def test_resolve_lets_operator_add_a_rule() -> None:
    override = {
        "rules": [{"event_id": 4688, "keys": ["NewProcessName"], "label": "proc"}]
    }
    resolved = resolve_dedup_rules(override)
    ids = {rule.event_id for rule in resolved}
    assert 4688 in ids
    # Defaults are still present (add, not replace).
    assert 4624 in ids and 3 in ids


def test_resolve_operator_rule_overrides_default_for_same_event_id() -> None:
    # An override for an event id already covered by a default REPLACES that
    # default's keys, so an operator can retune the tuple without editing code.
    override = {
        "rules": [
            {"event_id": 4624, "keys": ["TargetUserName"], "label": "logon-by-user"}
        ]
    }
    resolved = resolve_dedup_rules(override)
    rule_4624 = [r for r in resolved if r.event_id == 4624]
    assert len(rule_4624) == 1
    assert rule_4624[0].keys == ("TargetUserName",)
    # Replacement is IN PLACE: order stays [4624, 3], not pushed to the end.
    assert [r.event_id for r in resolved] == [4624, 3]


def test_resolve_suppresses_operator_rule_for_a_disabled_id() -> None:
    # disable wins over an add for the same id: an operator cannot accidentally
    # resurrect a rule they disabled in the same config.
    resolved = resolve_dedup_rules(
        {
            "disable": [4624],
            "rules": [{"event_id": 4624, "keys": ["TargetUserName"], "label": "x"}],
        }
    )
    assert 4624 not in {rule.event_id for rule in resolved}


def test_resolve_disable_coerces_float_and_string_ids() -> None:
    # disable and rules must coerce ids identically: a whole-number float id
    # disables and a digit-string disables (matching _coerce_rule's acceptance).
    resolved = resolve_dedup_rules({"disable": [4624.0, "3"]})
    ids = {rule.event_id for rule in resolved}
    assert 4624 not in ids  # float 4624.0 disabled it
    assert 3 not in ids  # "3" disabled it
    assert resolved == ()


def test_resolve_disable_bool_is_not_treated_as_event_id_one() -> None:
    # `True` must NOT coerce to event id 1: an operator rule for id 1 must survive
    # a `disable: [true]` typo, not be silently removed.
    resolved = resolve_dedup_rules(
        {
            "disable": [True],
            "rules": [{"event_id": 1, "keys": ["Foo"], "label": "one"}],
        }
    )
    ids = {rule.event_id for rule in resolved}
    assert 1 in ids  # bool True did NOT disable id 1
    # Defaults untouched too.
    assert 4624 in ids and 3 in ids


def test_resolve_operator_can_disable_a_default_rule() -> None:
    resolved = resolve_dedup_rules({"disable": [4624]})
    ids = {rule.event_id for rule in resolved}
    assert 4624 not in ids
    assert 3 in ids  # other defaults survive


# --- resolve_dedup_rules: hand-authored-YAML robustness --------------------
# CASE.yaml is hand-edited, so the contract ("a bad config never aborts the
# run") must hold for the common list-vs-scalar typos, not just well-formed input.


def test_resolve_survives_empty_disable_key() -> None:
    # `disable:` with no value parses to {"disable": None}; must not crash.
    assert resolve_dedup_rules({"disable": None}) == DEFAULT_RULES


def test_resolve_survives_scalar_disable_missing_the_list_dash() -> None:
    # `disable: 4624` (forgot the `-`) parses to {"disable": 4624}; treat it as a
    # single id rather than raising TypeError on a non-iterable int.
    resolved = resolve_dedup_rules({"disable": 4624})
    ids = {rule.event_id for rule in resolved}
    assert 4624 not in ids
    assert 3 in ids


def test_resolve_survives_scalar_rules_missing_the_list_dash() -> None:
    # `rules: 4688` (a scalar where a list was meant) must not crash; it coerces
    # to a single malformed spec that is dropped, leaving defaults intact.
    assert resolve_dedup_rules({"rules": 4688}) == DEFAULT_RULES


def test_resolve_accepts_single_rule_mapping_without_list_dash() -> None:
    # `rules:` with a bare mapping (no `-`) parses to {"rules": {..}}; treat the
    # mapping as one rule instead of silently iterating its keys and dropping it.
    override = {
        "rules": {"event_id": 4688, "keys": ["NewProcessName"], "label": "proc"}
    }
    resolved = resolve_dedup_rules(override)
    assert 4688 in {rule.event_id for rule in resolved}


def test_resolve_drops_malformed_rule_entries_but_keeps_valid_ones() -> None:
    # A bad entry (no keys) is dropped; a valid sibling in the same list survives.
    override = {
        "rules": [
            {"event_id": 4688},  # missing keys -> dropped
            {"event_id": 5140, "keys": ["ShareName"], "label": "share"},
            "not-a-mapping",  # dropped
        ]
    }
    ids = {rule.event_id for rule in resolve_dedup_rules(override)}
    assert 4688 not in ids
    assert 5140 in ids


def test_resolve_disable_accepts_string_ids() -> None:
    # A YAML id may arrive as a string ("4624"); the digit-string branch handles it.
    resolved = resolve_dedup_rules({"disable": ["4624", "not-a-number"]})
    ids = {rule.event_id for rule in resolved}
    assert 4624 not in ids
    assert 3 in ids  # non-numeric string ignored, other defaults survive


# --- mutation guards --------------------------------------------------------


def test_mutation_guard_uses_all_keys_not_just_first() -> None:
    # If collapse keyed on only the first field, two rows differing only in a
    # later field (ip) would wrongly collapse. Guards the full-tuple key.
    rows = [
        _logon("alice", "10.0.0.5", "3", 1),
        _logon("alice", "10.0.0.99", "3", 2),
    ]
    out = collapse_events(rows, DEFAULT_RULES)
    assert [r["RecordId"] for r in out] == [1, 2]


def test_mutation_guard_scopes_key_by_event_id() -> None:
    # A 4624 tuple and a Sysmon-EID3 tuple must never collide even if their key
    # values coincide; the event_id is part of the dedup key.
    rows = [
        {
            "EventId": 4624,
            "TargetUserName": "x",
            "IpAddress": "y",
            "LogonType": "z",
            "RecordId": 1,
        },
        {
            "EventId": 3,
            "Image": "x",
            "DestinationIp": "y",
            "DestinationPort": "z",
            "RecordId": 2,
        },
    ]
    out = collapse_events(rows, DEFAULT_RULES)
    assert [r["RecordId"] for r in out] == [1, 2]
