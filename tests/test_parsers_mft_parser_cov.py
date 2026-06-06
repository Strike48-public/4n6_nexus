"""Coverage tests for sift_find_evil.parsers.mft_parser.

Targets the timezone-normalization branch in ``MFTParser._parse_timestamp``
(lines 257-262): when the underlying comparator returns a timezone-naive
datetime, the parser must attach ``pytz.utc``.

In normal operation ``TimestampComparator.parse_iso8601`` always returns a
tz-aware datetime (it localizes naive inputs to UTC), so this defensive
normalization path is only reachable when the comparator yields a naive
datetime. We drive it by swapping in a fake comparator that returns a naive
datetime, mirroring the existing test-file conventions (real dataclasses,
``MFTParser`` instance, pytz for tz assertions).
"""

from __future__ import annotations

from datetime import datetime

import pytz

from sift_find_evil.parsers.mft_parser import MFTParser


class _NaiveComparator:
    """Fake comparator that returns a timezone-naive datetime.

    Duck-types the two methods ``_parse_timestamp`` calls: ``parse_iso8601``
    and ``is_null``. This forces the ``dt.tzinfo is None`` branch.
    """

    def __init__(self, naive_dt: datetime) -> None:
        self._naive_dt = naive_dt

    def parse_iso8601(self, timestamp_str: str) -> datetime:
        return self._naive_dt

    def is_null(self, dt: datetime) -> bool:
        return False


def test_parse_timestamp_attaches_utc_to_naive_comparator_result() -> None:
    """_parse_timestamp localizes a naive comparator result to UTC (lines 258, 260)."""
    parser = MFTParser()
    naive = datetime(2025, 3, 15, 14, 23, 45)  # no tzinfo
    parser.comparator = _NaiveComparator(naive)

    result = parser._parse_timestamp("2025-03-15T14:23:45")

    assert result is not None
    # Line 258 imported pytz; line 260 attached pytz.utc to the naive datetime.
    assert result.tzinfo is not None
    assert result.tzinfo == pytz.utc
    # Wall-clock components are preserved (replace, not convert).
    assert result.year == 2025
    assert result.month == 3
    assert result.day == 15
    assert result.hour == 14
    assert result.minute == 23
    assert result.second == 45


def test_parse_timestamp_aware_result_unchanged() -> None:
    """A tz-aware comparator result skips the naive branch and is returned as-is."""
    parser = MFTParser()
    aware = datetime(2025, 3, 15, 14, 23, 45, tzinfo=pytz.utc)
    parser.comparator = _NaiveComparator(aware)

    result = parser._parse_timestamp("2025-03-15T14:23:45Z")

    assert result is aware
    assert result.tzinfo == pytz.utc
