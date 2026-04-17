"""
Unit tests for TimestampComparator.
"""

import pytest
from datetime import datetime
import pytz
from sift_find_evil.validators.timestamp_comparator import TimestampComparator


class TestTimestampParsing:
    """Test timestamp parsing from various formats."""

    def test_parse_iso8601_with_microseconds(self):
        """Test parsing ISO 8601 with microseconds."""
        comparator = TimestampComparator()
        ts = "2025-03-15T14:23:45.123456Z"
        dt = comparator.parse_iso8601(ts)

        assert dt.year == 2025
        assert dt.month == 3
        assert dt.day == 15
        assert dt.hour == 14
        assert dt.minute == 23
        assert dt.second == 45
        assert dt.microsecond == 123456
        assert dt.tzinfo == pytz.utc

    def test_parse_iso8601_seven_digit_precision(self):
        """Test parsing ISO 8601 with 7-digit precision (Windows FILETIME)."""
        comparator = TimestampComparator()
        ts = "2025-03-15T14:23:45.1234567Z"
        dt = comparator.parse_iso8601(ts)

        assert dt.year == 2025
        assert dt.microsecond > 0  # Should capture some precision

    def test_parse_iso8601_no_fractional_seconds(self):
        """Test parsing ISO 8601 without fractional seconds."""
        comparator = TimestampComparator()
        ts = "2025-03-15T14:23:45Z"
        dt = comparator.parse_iso8601(ts)

        assert dt.second == 45
        assert dt.microsecond == 0

    def test_parse_invalid_timestamp(self):
        """Test parsing invalid timestamp raises ValueError."""
        comparator = TimestampComparator()

        with pytest.raises(ValueError):
            comparator.parse_iso8601("not a timestamp")


class TestNullDetection:
    """Test null/epoch timestamp detection."""

    def test_windows_epoch_detection(self):
        """Test detection of Windows epoch (1601-01-01)."""
        comparator = TimestampComparator()
        ts = "1601-01-01T00:00:00.0000000Z"
        dt = comparator.parse_iso8601(ts)

        assert comparator.is_null(dt) is True

    def test_unix_epoch_detection(self):
        """Test detection of Unix epoch (1970-01-01)."""
        comparator = TimestampComparator()
        unix_epoch = datetime(1970, 1, 1, tzinfo=pytz.utc)

        assert comparator.is_null(unix_epoch) is True

    def test_valid_timestamp_not_null(self):
        """Test valid timestamp is not detected as null."""
        comparator = TimestampComparator()
        ts = "2025-03-15T14:23:45Z"
        dt = comparator.parse_iso8601(ts)

        assert comparator.is_null(dt) is False


class TestTimestampComparison:
    """Test timestamp comparison with tolerance windows."""

    def test_timestamps_within_tolerance(self):
        """Test timestamps within tolerance are considered equal."""
        comparator = TimestampComparator(default_tolerance_seconds=300)

        dt1 = comparator.parse_iso8601("2025-03-15T14:00:00Z")
        dt2 = comparator.parse_iso8601("2025-03-15T14:04:00Z")  # 4 minutes later

        result = comparator.compare(dt1, dt2)
        assert result == 0  # Within 5-minute tolerance

    def test_timestamps_beyond_tolerance(self):
        """Test timestamps beyond tolerance are not equal."""
        comparator = TimestampComparator(default_tolerance_seconds=300)

        dt1 = comparator.parse_iso8601("2025-03-15T14:00:00Z")
        dt2 = comparator.parse_iso8601("2025-03-15T14:10:00Z")  # 10 minutes later

        result = comparator.compare(dt1, dt2)
        assert result == -1  # dt1 is earlier

    def test_compare_with_null_returns_none(self):
        """Test comparison with null timestamp returns None."""
        comparator = TimestampComparator()

        dt1 = comparator.parse_iso8601("2025-03-15T14:00:00Z")
        dt2 = comparator.parse_iso8601("1601-01-01T00:00:00Z")  # Null

        result = comparator.compare(dt1, dt2)
        assert result is None


class TestCausalityViolation:
    """Test detection of causality violations (file modified after execution)."""

    def test_no_violation_normal_case(self):
        """Test no violation when file created before execution."""
        comparator = TimestampComparator()

        file_modified = comparator.parse_iso8601("2025-03-15T14:00:00Z")
        process_executed = comparator.parse_iso8601("2025-03-15T14:05:00Z")

        violation = comparator.detect_causality_violation(file_modified, process_executed)
        assert violation is None  # No violation

    def test_violation_file_modified_after_execution(self):
        """Test violation detected when file modified after execution."""
        comparator = TimestampComparator()

        file_modified = comparator.parse_iso8601("2025-03-15T14:30:00Z")
        process_executed = comparator.parse_iso8601("2025-03-15T14:20:00Z")  # 10 minutes earlier

        violation = comparator.detect_causality_violation(file_modified, process_executed)

        assert violation is not None
        assert violation['type'] == 'causality_violation'
        assert violation['time_delta_seconds'] == 600  # 10 minutes

    def test_violation_severity_high_for_large_delta(self):
        """Test high severity for large time deltas."""
        comparator = TimestampComparator()

        file_modified = comparator.parse_iso8601("2025-03-15T15:00:00Z")
        process_executed = comparator.parse_iso8601("2025-03-15T14:00:00Z")

        violation = comparator.detect_causality_violation(file_modified, process_executed)

        assert violation['severity'] == 'high'  # > 10 minutes


class TestTimestomping:
    """Test detection of timestamp manipulation ($SI vs $FN)."""

    def test_no_timestomping_normal_case(self):
        """Test no timestomping when $SI and $FN agree."""
        comparator = TimestampComparator()

        si_modified = comparator.parse_iso8601("2025-03-15T14:00:00Z")
        fn_modified = comparator.parse_iso8601("2025-03-15T14:00:30Z")  # 30 seconds later

        timestomping = comparator.detect_timestomping(si_modified, fn_modified)
        assert timestomping is None  # Within 1-minute tolerance

    def test_timestomping_si_earlier_than_fn(self):
        """Test timestomping detected when $SI earlier than $FN."""
        comparator = TimestampComparator()

        si_modified = comparator.parse_iso8601("2025-03-15T10:00:00Z")
        fn_modified = comparator.parse_iso8601("2025-03-15T14:00:00Z")  # 4 hours later

        timestomping = comparator.detect_timestomping(si_modified, fn_modified)

        assert timestomping is not None
        assert timestomping['type'] == 'timestomping_detected'
        assert timestomping['severity'] == 'critical'
        assert timestomping['time_delta_seconds'] < 0  # Negative = SI earlier

    def test_timestomping_null_timestamp(self):
        """Test timestomping detection with null timestamp."""
        comparator = TimestampComparator()

        si_modified = comparator.parse_iso8601("1601-01-01T00:00:00Z")  # Null
        fn_modified = comparator.parse_iso8601("2025-03-15T14:00:00Z")

        timestomping = comparator.detect_timestomping(si_modified, fn_modified)
        assert timestomping is None  # Cannot determine


class TestTimeDelta:
    """Test time delta calculations."""

    def test_time_delta_positive(self):
        """Test positive time delta (dt1 > dt2)."""
        comparator = TimestampComparator()

        dt1 = comparator.parse_iso8601("2025-03-15T14:10:00Z")
        dt2 = comparator.parse_iso8601("2025-03-15T14:00:00Z")

        delta = comparator.time_delta_seconds(dt1, dt2)
        assert delta == 600  # 10 minutes

    def test_time_delta_negative(self):
        """Test negative time delta (dt1 < dt2)."""
        comparator = TimestampComparator()

        dt1 = comparator.parse_iso8601("2025-03-15T14:00:00Z")
        dt2 = comparator.parse_iso8601("2025-03-15T14:10:00Z")

        delta = comparator.time_delta_seconds(dt1, dt2)
        assert delta == -600  # -10 minutes

    def test_time_delta_with_null(self):
        """Test time delta with null timestamp returns None."""
        comparator = TimestampComparator()

        dt1 = comparator.parse_iso8601("2025-03-15T14:00:00Z")
        dt2 = comparator.parse_iso8601("1601-01-01T00:00:00Z")  # Null

        delta = comparator.time_delta_seconds(dt1, dt2)
        assert delta is None


class TestFormatting:
    """Test timestamp formatting."""

    def test_format_with_microseconds(self):
        """Test formatting with microseconds."""
        comparator = TimestampComparator()
        dt = comparator.parse_iso8601("2025-03-15T14:23:45.123456Z")

        formatted = comparator.format_timestamp(dt, include_microseconds=True)
        assert ".123456Z" in formatted

    def test_format_without_microseconds(self):
        """Test formatting without microseconds."""
        comparator = TimestampComparator()
        dt = comparator.parse_iso8601("2025-03-15T14:23:45.123456Z")

        formatted = comparator.format_timestamp(dt, include_microseconds=False)
        assert "2025-03-15T14:23:45Z" == formatted

    def test_format_null_timestamp(self):
        """Test formatting null timestamp."""
        comparator = TimestampComparator()
        dt = comparator.parse_iso8601("1601-01-01T00:00:00Z")

        formatted = comparator.format_timestamp(dt)
        assert formatted == "NULL"
