"""Tests for the shared canonical-JSON serializer (PR #3 review nit #1/#4).

Taylor's review flagged the canonical-JSON idiom
``json.dumps(payload, sort_keys=True, separators=(",",":"), default=str)``
duplicated across audit/models, custody/receipt, custody/signing, and
approval/manager - a drift risk (a future change must land in every copy or the
standalone verifier diverges). This is the single source of truth.
"""

from sift_find_evil.canonical import canonical_bytes, canonical_json


def test_sorts_keys_and_strips_whitespace():
    out = canonical_json({"b": 1, "a": 2})
    assert out == '{"a":2,"b":1}'


def test_reproducible_regardless_of_input_order():
    assert canonical_json({"x": 1, "y": 2}) == canonical_json({"y": 2, "x": 1})


def test_default_str_handles_non_json_types():
    from datetime import datetime, timezone

    ts = datetime(2026, 7, 21, tzinfo=timezone.utc)
    # A datetime is not natively JSON-serializable; default=str must coerce it.
    out = canonical_json({"ts": ts})
    assert "2026-07-21" in out


def test_bytes_helper_is_utf8_of_the_string():
    payload = {"a": 1, "b": "x"}
    assert canonical_bytes(payload) == canonical_json(payload).encode("utf-8")


def test_nested_structures_are_stably_ordered():
    a = canonical_json({"outer": {"z": 1, "a": 2}, "list": [3, 1, 2]})
    b = canonical_json({"list": [3, 1, 2], "outer": {"a": 2, "z": 1}})
    assert a == b
    # List order is preserved (only dict keys are sorted).
    assert '"list":[3,1,2]' in a
