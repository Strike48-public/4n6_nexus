"""Comprehensive tests for prefetch_parser.py to improve coverage.

Missing lines from coverage report: 37-41, 49-50, 63-70, 98, 156-159, 178,
181-182, 196-200, 214-225, 239-246, 259-262, 278-301
"""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import Mock

import pytest

from sift_find_evil.parsers.prefetch_parser import PrefetchEntry, PrefetchParser


def test_get_all_run_times_with_no_timestamps():
    """Test get_all_run_times() returns empty list when no timestamps."""
    entry = PrefetchEntry(
        source_filename="test.pf",
        executable="test.exe",
        run_count=0,
        last_run_time=None,
        previous_run_times=[],
    )

    result = entry.get_all_run_times()

    assert result == []


def test_get_all_run_times_with_only_last_run_time():
    """Test get_all_run_times() returns list with only last_run_time."""
    time1 = datetime(2023, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    entry = PrefetchEntry(
        source_filename="test.pf",
        executable="test.exe",
        run_count=1,
        last_run_time=time1,
        previous_run_times=[],
    )

    result = entry.get_all_run_times()

    assert result == [time1]


def test_get_all_run_times_with_multiple_times():
    """Test get_all_run_times() returns all timestamps."""
    time1 = datetime(2023, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    time2 = datetime(2023, 1, 1, 11, 0, 0, tzinfo=timezone.utc)
    time3 = datetime(2023, 1, 1, 10, 0, 0, tzinfo=timezone.utc)

    entry = PrefetchEntry(
        source_filename="test.pf",
        executable="test.exe",
        run_count=3,
        last_run_time=time1,
        previous_run_times=[time2, time3],
    )

    result = entry.get_all_run_times()

    assert result == [time1, time2, time3]


def test_get_first_run_time_with_no_timestamps():
    """Test get_first_run_time() returns None when no timestamps."""
    entry = PrefetchEntry(
        source_filename="test.pf",
        executable="test.exe",
        run_count=0,
        last_run_time=None,
        previous_run_times=[],
    )

    result = entry.get_first_run_time()

    assert result is None


def test_get_first_run_time_returns_earliest():
    """Test get_first_run_time() returns the earliest timestamp."""
    time1 = datetime(2023, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    time2 = datetime(2023, 1, 1, 11, 0, 0, tzinfo=timezone.utc)
    time3 = datetime(2023, 1, 1, 10, 0, 0, tzinfo=timezone.utc)

    entry = PrefetchEntry(
        source_filename="test.pf",
        executable="test.exe",
        run_count=3,
        last_run_time=time1,
        previous_run_times=[time2, time3],
    )

    result = entry.get_first_run_time()

    assert result == time3  # Earliest time


def test_was_executed_at_returns_true_within_tolerance():
    """Test was_executed_at() returns True when within tolerance window."""
    run_time = datetime(2023, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    target_time = datetime(2023, 1, 1, 12, 0, 3, tzinfo=timezone.utc)  # 3 seconds later

    entry = PrefetchEntry(
        source_filename="test.pf",
        executable="test.exe",
        run_count=1,
        last_run_time=run_time,
    )

    result = entry.was_executed_at(target_time, tolerance_seconds=5)

    assert result is True


def test_was_executed_at_returns_false_outside_tolerance():
    """Test was_executed_at() returns False when outside tolerance window."""
    run_time = datetime(2023, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    target_time = datetime(
        2023, 1, 1, 12, 0, 10, tzinfo=timezone.utc
    )  # 10 seconds later

    entry = PrefetchEntry(
        source_filename="test.pf",
        executable="test.exe",
        run_count=1,
        last_run_time=run_time,
    )

    result = entry.was_executed_at(target_time, tolerance_seconds=5)

    assert result is False


def test_was_executed_at_checks_all_run_times():
    """Test was_executed_at() checks all run times, not just last."""
    time1 = datetime(2023, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    time2 = datetime(2023, 1, 1, 11, 0, 0, tzinfo=timezone.utc)
    target_time = datetime(2023, 1, 1, 11, 0, 2, tzinfo=timezone.utc)  # Match time2

    entry = PrefetchEntry(
        source_filename="test.pf",
        executable="test.exe",
        run_count=2,
        last_run_time=time1,
        previous_run_times=[time2],
    )

    result = entry.was_executed_at(target_time, tolerance_seconds=5)

    assert result is True


def test_parse_csv_raises_file_not_found():
    """Test parse_csv() raises FileNotFoundError for missing file."""
    parser = PrefetchParser()

    with pytest.raises(FileNotFoundError, match="Prefetch CSV not found"):
        parser.parse_csv("/tmp/nonexistent_prefetch.csv")


def test_parse_row_handles_exception_returns_none():
    """Test _parse_row() returns None when parsing fails."""
    parser = PrefetchParser()

    # Invalid row that will cause parsing error
    invalid_row = {"RunCount": "not_a_number"}

    result = parser._parse_row(invalid_row)

    assert result is None


def test_parse_timestamp_returns_none_for_null_timestamp():
    """Test _parse_timestamp() returns None for null timestamps."""
    parser = PrefetchParser()

    # Windows epoch is treated as null
    result = parser._parse_timestamp("1601-01-01T00:00:00")

    assert result is None


def test_parse_timestamp_returns_none_on_exception():
    """Test _parse_timestamp() returns None when parsing fails."""
    parser = PrefetchParser()

    # Invalid timestamp
    result = parser._parse_timestamp("invalid_timestamp")

    assert result is None


def test_find_by_executable_case_sensitive_match():
    """Test find_by_executable() with case_sensitive=True."""
    entry1 = PrefetchEntry(
        source_filename="test.pf",
        executable="Malware.exe",
        run_count=1,
        last_run_time=None,
    )
    entry2 = PrefetchEntry(
        source_filename="test2.pf",
        executable="malware.exe",  # Different case
        run_count=1,
        last_run_time=None,
    )

    parser = PrefetchParser()
    result = parser.find_by_executable(
        [entry1, entry2], "Malware.exe", case_sensitive=True
    )

    assert len(result) == 1
    assert result[0] == entry1


def test_find_by_executable_case_insensitive_match():
    """Test find_by_executable() with case_sensitive=False (default)."""
    entry1 = PrefetchEntry(
        source_filename="test.pf",
        executable="Malware.exe",
        run_count=1,
        last_run_time=None,
    )
    entry2 = PrefetchEntry(
        source_filename="test2.pf",
        executable="malware.exe",
        run_count=1,
        last_run_time=None,
    )

    parser = PrefetchParser()
    result = parser.find_by_executable(
        [entry1, entry2], "MALWARE.EXE", case_sensitive=False
    )

    assert len(result) == 2


def test_find_by_dll_loaded_case_sensitive():
    """Test find_by_dll_loaded() with case_sensitive=True."""
    entry1 = PrefetchEntry(
        source_filename="test.pf",
        executable="app.exe",
        run_count=1,
        last_run_time=None,
        files_loaded=["C:\\Windows\\System32\\kernel32.dll"],
    )
    entry2 = PrefetchEntry(
        source_filename="test2.pf",
        executable="app2.exe",
        run_count=1,
        last_run_time=None,
        files_loaded=["C:\\Windows\\System32\\KERNEL32.DLL"],  # Different case
    )

    parser = PrefetchParser()
    result = parser.find_by_dll_loaded(
        [entry1, entry2], "kernel32.dll", case_sensitive=True
    )

    assert len(result) == 1
    assert result[0] == entry1


def test_find_by_dll_loaded_case_insensitive():
    """Test find_by_dll_loaded() with case_sensitive=False."""
    entry1 = PrefetchEntry(
        source_filename="test.pf",
        executable="app.exe",
        run_count=1,
        last_run_time=None,
        files_loaded=["C:\\Windows\\System32\\kernel32.dll"],
    )
    entry2 = PrefetchEntry(
        source_filename="test2.pf",
        executable="app2.exe",
        run_count=1,
        last_run_time=None,
        files_loaded=["C:\\Windows\\System32\\KERNEL32.DLL"],
    )

    parser = PrefetchParser()
    result = parser.find_by_dll_loaded(
        [entry1, entry2], "KERNEL32", case_sensitive=False
    )

    assert len(result) == 2


def test_get_most_recent_executions_filters_null_last_run_time():
    """Test get_most_recent_executions() filters entries with null last_run_time."""
    time1 = datetime(2023, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    entry1 = PrefetchEntry(
        source_filename="test1.pf",
        executable="app1.exe",
        run_count=1,
        last_run_time=time1,
    )
    entry2 = PrefetchEntry(
        source_filename="test2.pf",
        executable="app2.exe",
        run_count=1,
        last_run_time=None,  # Should be filtered out
    )

    parser = PrefetchParser()
    result = parser.get_most_recent_executions([entry1, entry2], limit=10)

    assert len(result) == 1
    assert result[0] == entry1


def test_get_most_recent_executions_sorts_by_time():
    """Test get_most_recent_executions() sorts by last_run_time descending."""
    time1 = datetime(2023, 1, 1, 10, 0, 0, tzinfo=timezone.utc)
    time2 = datetime(2023, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    time3 = datetime(2023, 1, 1, 11, 0, 0, tzinfo=timezone.utc)

    entry1 = PrefetchEntry(
        source_filename="test1.pf",
        executable="app1.exe",
        run_count=1,
        last_run_time=time1,
    )
    entry2 = PrefetchEntry(
        source_filename="test2.pf",
        executable="app2.exe",
        run_count=1,
        last_run_time=time2,
    )
    entry3 = PrefetchEntry(
        source_filename="test3.pf",
        executable="app3.exe",
        run_count=1,
        last_run_time=time3,
    )

    parser = PrefetchParser()
    result = parser.get_most_recent_executions([entry1, entry2, entry3], limit=10)

    assert len(result) == 3
    assert result[0] == entry2  # Newest
    assert result[1] == entry3
    assert result[2] == entry1  # Oldest


def test_get_frequently_run_filters_by_min_run_count():
    """Test get_frequently_run() filters entries below min_run_count."""
    entry1 = PrefetchEntry(
        source_filename="test1.pf",
        executable="app1.exe",
        run_count=5,
        last_run_time=None,
    )
    entry2 = PrefetchEntry(
        source_filename="test2.pf",
        executable="app2.exe",
        run_count=15,
        last_run_time=None,
    )
    entry3 = PrefetchEntry(
        source_filename="test3.pf",
        executable="app3.exe",
        run_count=20,
        last_run_time=None,
    )

    parser = PrefetchParser()
    result = parser.get_frequently_run([entry1, entry2, entry3], min_run_count=10)

    assert len(result) == 2
    assert entry1 not in result
    assert entry2 in result
    assert entry3 in result


def test_get_frequently_run_sorts_by_run_count():
    """Test get_frequently_run() sorts by run_count descending."""
    entry1 = PrefetchEntry(
        source_filename="test1.pf",
        executable="app1.exe",
        run_count=15,
        last_run_time=None,
    )
    entry2 = PrefetchEntry(
        source_filename="test2.pf",
        executable="app2.exe",
        run_count=20,
        last_run_time=None,
    )
    entry3 = PrefetchEntry(
        source_filename="test3.pf",
        executable="app3.exe",
        run_count=10,
        last_run_time=None,
    )

    parser = PrefetchParser()
    result = parser.get_frequently_run([entry1, entry2, entry3], min_run_count=10)

    assert result[0] == entry2  # Highest count
    assert result[1] == entry1
    assert result[2] == entry3  # Lowest count


def test_correlate_with_mft_no_matching_mft_entry():
    """Test correlate_with_mft() returns None when no MFT match found."""
    prefetch_entry = PrefetchEntry(
        source_filename="test.pf",
        executable="app.exe",
        run_count=1,
        last_run_time=datetime(2023, 1, 1, 12, 0, 0, tzinfo=timezone.utc),
    )

    mock_mft_entry = Mock()
    mock_mft_entry.file_name = "different.exe"

    parser = PrefetchParser()
    result = parser.correlate_with_mft(
        prefetch_entry, [mock_mft_entry], parser.comparator
    )

    assert result is None


def test_correlate_with_mft_no_timestamps():
    """Test correlate_with_mft() returns None when timestamps are missing."""
    prefetch_entry = PrefetchEntry(
        source_filename="test.pf",
        executable="app.exe",
        run_count=1,
        last_run_time=None,  # No timestamp
    )

    mock_mft_entry = Mock()
    mock_mft_entry.file_name = "app.exe"
    mock_mft_entry.get_modification_time.return_value = None

    parser = PrefetchParser()
    result = parser.correlate_with_mft(
        prefetch_entry, [mock_mft_entry], parser.comparator
    )

    assert result is None


def test_correlate_with_mft_success():
    """Test correlate_with_mft() returns correlation result when match found."""
    prefetch_time = datetime(2023, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    mft_time = datetime(2023, 1, 1, 11, 50, 0, tzinfo=timezone.utc)

    prefetch_entry = PrefetchEntry(
        source_filename="test.pf",
        executable="app.exe",
        run_count=1,
        last_run_time=prefetch_time,
    )

    mock_mft_entry = Mock()
    mock_mft_entry.file_name = "app.exe"
    mock_mft_entry.get_modification_time.return_value = mft_time

    parser = PrefetchParser()
    result = parser.correlate_with_mft(
        prefetch_entry, [mock_mft_entry], parser.comparator
    )

    assert result is not None
    assert result["mft_entry"] == mock_mft_entry
    assert result["prefetch_entry"] == prefetch_entry
    assert result["mft_modified"] == mft_time
    assert result["prefetch_last_run"] == prefetch_time
    assert "time_delta_seconds" in result
    assert "causality_violation" in result
