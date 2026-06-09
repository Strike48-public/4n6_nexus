"""Tests for Event Log parser."""

import json
from datetime import datetime, timezone

import pytest

from sift_find_evil.parsers.evtx_parser import EventLogEntry, EventLogParser


@pytest.fixture
def parser():
    """Create EventLogParser instance."""
    return EventLogParser()


@pytest.fixture
def sample_entries():
    """Create sample event log entries for testing."""
    return [
        EventLogEntry(
            time_created=datetime(2024, 1, 15, 10, 30, 0, tzinfo=timezone.utc),
            event_id=4688,
            record_id=1001,
            computer="DESKTOP-01",
            channel="Security",
            level="Information",
            payload_data1="C:\\Windows\\System32\\cmd.exe",
            payload_data6="cmd.exe /c echo test",
            payload_json={
                "EventData": {
                    "Data": [
                        {
                            "@Name": "NewProcessName",
                            "#text": "C:\\Windows\\System32\\cmd.exe",
                        },
                        {"@Name": "CommandLine", "#text": "cmd.exe /c echo test"},
                    ]
                }
            },
        ),
        EventLogEntry(
            time_created=datetime(2024, 1, 15, 10, 31, 0, tzinfo=timezone.utc),
            event_id=4688,
            record_id=1002,
            computer="DESKTOP-01",
            channel="Security",
            level="Information",
            payload_data1="C:\\Tools\\malware.exe",
            payload_json={
                "EventData": {
                    "Data": [
                        {"@Name": "NewProcessName", "#text": "C:\\Tools\\malware.exe"},
                    ]
                }
            },
        ),
        EventLogEntry(
            time_created=datetime(2024, 1, 15, 10, 32, 0, tzinfo=timezone.utc),
            event_id=4624,
            record_id=1003,
            computer="DESKTOP-01",
            channel="Security",
            level="Information",
        ),
    ]


def test_event_log_entry_is_process_creation():
    """Test is_process_creation for Event ID 4688 and 592."""
    entry_4688 = EventLogEntry(
        time_created=datetime.now(timezone.utc),
        event_id=4688,
        record_id=1,
        computer="TEST",
        channel="Security",
        level="Information",
    )
    assert entry_4688.is_process_creation()

    entry_592 = EventLogEntry(
        time_created=datetime.now(timezone.utc),
        event_id=592,
        record_id=2,
        computer="TEST",
        channel="Security",
        level="Information",
    )
    assert entry_592.is_process_creation()

    entry_other = EventLogEntry(
        time_created=datetime.now(timezone.utc),
        event_id=4624,
        record_id=3,
        computer="TEST",
        channel="Security",
        level="Information",
    )
    assert not entry_other.is_process_creation()


def test_get_process_name_from_json():
    """Test get_process_name extracts from JSON payload."""
    entry = EventLogEntry(
        time_created=datetime.now(timezone.utc),
        event_id=4688,
        record_id=1,
        computer="TEST",
        channel="Security",
        level="Information",
        payload_json={
            "EventData": {
                "Data": [
                    {
                        "@Name": "NewProcessName",
                        "#text": "C:\\Windows\\System32\\notepad.exe",
                    }
                ]
            }
        },
    )
    assert entry.get_process_name() == "C:\\Windows\\System32\\notepad.exe"


def test_get_process_name_fallback_to_payload_data1():
    """Test get_process_name falls back to payload_data1."""
    entry = EventLogEntry(
        time_created=datetime.now(timezone.utc),
        event_id=4688,
        record_id=1,
        computer="TEST",
        channel="Security",
        level="Information",
        payload_data1="C:\\Tools\\app.exe",
    )
    assert entry.get_process_name() == "C:\\Tools\\app.exe"


def test_get_process_name_returns_none_for_non_process_event():
    """Test get_process_name returns None for non-process events."""
    entry = EventLogEntry(
        time_created=datetime.now(timezone.utc),
        event_id=4624,
        record_id=1,
        computer="TEST",
        channel="Security",
        level="Information",
    )
    assert entry.get_process_name() is None


def test_get_process_name_json_exception():
    """Test get_process_name handles malformed JSON gracefully."""
    entry = EventLogEntry(
        time_created=datetime.now(timezone.utc),
        event_id=4688,
        record_id=1,
        computer="TEST",
        channel="Security",
        level="Information",
        payload_json={"EventData": "invalid"},  # Not a dict
        payload_data1="C:\\Fallback\\app.exe",
    )
    # Should fall back to payload_data1
    assert entry.get_process_name() == "C:\\Fallback\\app.exe"


def test_get_command_line_from_json():
    """Test get_command_line extracts from JSON payload."""
    entry = EventLogEntry(
        time_created=datetime.now(timezone.utc),
        event_id=4688,
        record_id=1,
        computer="TEST",
        channel="Security",
        level="Information",
        payload_json={
            "EventData": {
                "Data": [{"@Name": "CommandLine", "#text": "notepad.exe test.txt"}]
            }
        },
    )
    assert entry.get_command_line() == "notepad.exe test.txt"


def test_get_command_line_fallback_to_payload_data6():
    """Test get_command_line falls back to payload_data6."""
    entry = EventLogEntry(
        time_created=datetime.now(timezone.utc),
        event_id=4688,
        record_id=1,
        computer="TEST",
        channel="Security",
        level="Information",
        payload_data6="cmd.exe /c dir",
    )
    assert entry.get_command_line() == "cmd.exe /c dir"


def test_get_command_line_returns_none_for_non_process_event():
    """Test get_command_line returns None for non-process events."""
    entry = EventLogEntry(
        time_created=datetime.now(timezone.utc),
        event_id=4624,
        record_id=1,
        computer="TEST",
        channel="Security",
        level="Information",
    )
    assert entry.get_command_line() is None


def test_get_command_line_json_exception():
    """Test get_command_line handles malformed JSON gracefully."""
    entry = EventLogEntry(
        time_created=datetime.now(timezone.utc),
        event_id=4688,
        record_id=1,
        computer="TEST",
        channel="Security",
        level="Information",
        payload_json={"EventData": []},  # Not a dict
        payload_data6="fallback command",
    )
    # Should fall back to payload_data6
    assert entry.get_command_line() == "fallback command"


def test_get_executable_name_windows_path():
    """Test get_executable_name extracts from Windows path."""
    entry = EventLogEntry(
        time_created=datetime.now(timezone.utc),
        event_id=4688,
        record_id=1,
        computer="TEST",
        channel="Security",
        level="Information",
        payload_data1="C:\\Windows\\System32\\notepad.exe",
    )
    assert entry.get_executable_name() == "notepad.exe"


def test_get_executable_name_unix_path():
    """Test get_executable_name extracts from Unix path."""
    entry = EventLogEntry(
        time_created=datetime.now(timezone.utc),
        event_id=4688,
        record_id=1,
        computer="TEST",
        channel="Security",
        level="Information",
        payload_data1="/usr/bin/bash",
    )
    assert entry.get_executable_name() == "bash"


def test_get_executable_name_no_path():
    """Test get_executable_name returns name when no path separators."""
    entry = EventLogEntry(
        time_created=datetime.now(timezone.utc),
        event_id=4688,
        record_id=1,
        computer="TEST",
        channel="Security",
        level="Information",
        payload_data1="app.exe",
    )
    assert entry.get_executable_name() == "app.exe"


def test_get_executable_name_returns_none_when_no_process():
    """Test get_executable_name returns None when no process name."""
    entry = EventLogEntry(
        time_created=datetime.now(timezone.utc),
        event_id=4688,
        record_id=1,
        computer="TEST",
        channel="Security",
        level="Information",
    )
    assert entry.get_executable_name() is None


def test_parse_csv_file_not_found(parser):
    """Test parse_csv raises FileNotFoundError for missing file."""
    with pytest.raises(FileNotFoundError, match="Event Log CSV not found"):
        parser.parse_csv("/nonexistent/path.csv")


def test_parse_csv_with_filter(parser, tmp_path):
    """Test parse_csv with event ID filter."""
    csv_file = tmp_path / "events.csv"
    csv_file.write_text(
        "TimeCreated,EventId,RecordId,Computer,Channel,Level\n"
        "2024-01-15T10:30:00Z,4688,1001,DESKTOP-01,Security,Information\n"
        "2024-01-15T10:31:00Z,4624,1002,DESKTOP-01,Security,Information\n"
    )

    entries = parser.parse_csv(str(csv_file), filter_event_ids=[4688])
    assert len(entries) == 1
    assert entries[0].event_id == 4688


def test_parse_csv_captures_remote_host(parser, tmp_path):
    """RemoteHost column is captured for lateral-movement source attribution."""
    csv_file = tmp_path / "events.csv"
    csv_file.write_text(
        "TimeCreated,EventId,RecordId,Computer,Channel,Level,RemoteHost\n"
        "2024-01-15T10:31:00Z,4624,1002,DC01,Security,Information,WKSTN-07 (10.0.0.7)\n"
    )

    entries = parser.parse_csv(str(csv_file))
    assert len(entries) == 1
    assert entries[0].remote_host == "WKSTN-07 (10.0.0.7)"


def test_parse_csv_remote_host_absent_defaults_none(parser, tmp_path):
    """A CSV without a RemoteHost column leaves remote_host as None."""
    csv_file = tmp_path / "events.csv"
    csv_file.write_text(
        "TimeCreated,EventId,RecordId,Computer,Channel,Level\n"
        "2024-01-15T10:31:00Z,4624,1002,DC01,Security,Information\n"
    )

    entries = parser.parse_csv(str(csv_file))
    assert len(entries) == 1
    assert entries[0].remote_host is None


def test_parse_row_with_invalid_timestamp(parser):
    """Test _parse_row returns None for invalid timestamp."""
    row = {
        "TimeCreated": "invalid-timestamp",
        "EventId": "4688",
        "RecordId": "1001",
        "Computer": "TEST",
        "Channel": "Security",
        "Level": "Information",
    }
    result = parser._parse_row(row)
    assert result is None


def test_parse_row_with_json_payload(parser):
    """Test _parse_row parses JSON payload."""
    payload_json = {
        "EventData": {
            "Data": [{"@Name": "NewProcessName", "#text": "C:\\Windows\\notepad.exe"}]
        }
    }
    row = {
        "TimeCreated": "2024-01-15T10:30:00Z",
        "EventId": "4688",
        "RecordId": "1001",
        "Computer": "TEST",
        "Channel": "Security",
        "Level": "Information",
        "Payload": json.dumps(payload_json),
    }
    result = parser._parse_row(row)
    assert result is not None
    assert result.payload_json == payload_json


def test_parse_row_with_invalid_json(parser):
    """Test _parse_row handles invalid JSON in Payload."""
    row = {
        "TimeCreated": "2024-01-15T10:30:00Z",
        "EventId": "4688",
        "RecordId": "1001",
        "Computer": "TEST",
        "Channel": "Security",
        "Level": "Information",
        "Payload": "invalid json{",
    }
    result = parser._parse_row(row)
    assert result is not None
    assert result.payload_json is None


def test_parse_row_with_exception(parser):
    """Test _parse_row returns None when exception occurs."""
    row = {
        "TimeCreated": "2024-01-15T10:30:00Z",
        "EventId": "not-a-number",  # Will cause int() to fail
        "RecordId": "1001",
        "Computer": "TEST",
        "Channel": "Security",
        "Level": "Information",
    }
    result = parser._parse_row(row)
    assert result is None


def test_parse_timestamp_with_null_value(parser):
    """Test _parse_timestamp returns None for null/empty values."""
    assert parser._parse_timestamp(None) is None
    assert parser._parse_timestamp("") is None
    assert parser._parse_timestamp("   ") is None


def test_parse_timestamp_with_null_datetime(parser):
    """Test _parse_timestamp returns None for null datetime (1601-01-01)."""
    # Mock comparator.is_null to return True
    from unittest.mock import Mock

    parser.comparator.is_null = Mock(return_value=True)
    parser.comparator.parse_iso8601 = Mock(return_value=datetime(1601, 1, 1))

    result = parser._parse_timestamp("1601-01-01T00:00:00Z")
    assert result is None


def test_parse_timestamp_with_exception(parser):
    """Test _parse_timestamp returns None when parse fails."""
    result = parser._parse_timestamp("invalid-timestamp")
    assert result is None


def test_get_process_creation_events(parser, sample_entries):
    """Test get_process_creation_events filters 4688/592 events."""
    result = parser.get_process_creation_events(sample_entries)
    assert len(result) == 2
    assert all(e.event_id in [4688, 592] for e in result)


def test_find_by_executable_case_insensitive(parser, sample_entries):
    """Test find_by_executable case-insensitive search."""
    result = parser.find_by_executable(
        sample_entries, "MALWARE.EXE", case_sensitive=False
    )
    assert len(result) == 1
    assert result[0].event_id == 4688


def test_find_by_executable_case_sensitive(parser, sample_entries):
    """Test find_by_executable case-sensitive search."""
    result = parser.find_by_executable(
        sample_entries, "malware.exe", case_sensitive=True
    )
    assert len(result) == 1

    result = parser.find_by_executable(
        sample_entries, "MALWARE.EXE", case_sensitive=True
    )
    assert len(result) == 0


def test_find_by_executable_no_matches(parser, sample_entries):
    """Test find_by_executable returns empty list when no matches."""
    result = parser.find_by_executable(sample_entries, "nonexistent.exe")
    assert len(result) == 0


def test_find_by_time_window(parser, sample_entries):
    """Test find_by_time_window finds events within tolerance."""
    target_time = datetime(2024, 1, 15, 10, 30, 30, tzinfo=timezone.utc)
    result = parser.find_by_time_window(
        sample_entries, target_time, tolerance_seconds=60
    )
    # Within 60s of 10:30:30 = 10:29:30 to 10:31:30
    # Entries at 10:30:00 (30s delta) and 10:31:00 (30s delta) both match
    assert len(result) == 2
    assert result[0].record_id in [1001, 1002]


def test_find_by_time_window_no_matches(parser, sample_entries):
    """Test find_by_time_window returns empty list when no matches."""
    target_time = datetime(2024, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
    result = parser.find_by_time_window(
        sample_entries, target_time, tolerance_seconds=60
    )
    assert len(result) == 0


def test_resolve_contradiction_no_events(parser):
    """Test resolve_contradiction when no Event ID 4688 found."""
    result = parser.resolve_contradiction(
        executable_name="nonexistent.exe",
        prefetch_time=datetime.now(timezone.utc),
        mft_time=datetime.now(timezone.utc),
        entries=[],
    )
    assert result["resolution"] == "uncertain_no_event_log"
    assert result["event_count"] == 0


def test_resolve_contradiction_confirms_prefetch(parser, sample_entries):
    """Test resolve_contradiction confirms prefetch time."""
    prefetch_time = datetime(2024, 1, 15, 10, 31, 15, tzinfo=timezone.utc)
    mft_time = datetime(2024, 1, 15, 9, 0, 0, tzinfo=timezone.utc)

    result = parser.resolve_contradiction(
        executable_name="malware.exe",
        prefetch_time=prefetch_time,
        mft_time=mft_time,
        entries=sample_entries,
    )

    assert result["resolution"] == "event_log_confirms_prefetch"
    assert result["confidence_recovery"] == 0.30
    assert result["event_count"] == 1


def test_resolve_contradiction_mismatch(parser, sample_entries):
    """Test resolve_contradiction when events outside tolerance."""
    prefetch_time = datetime(2024, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
    mft_time = datetime(2024, 1, 15, 9, 0, 0, tzinfo=timezone.utc)

    result = parser.resolve_contradiction(
        executable_name="malware.exe",
        prefetch_time=prefetch_time,
        mft_time=mft_time,
        entries=sample_entries,
        tolerance_seconds=60,
    )

    assert result["resolution"] == "event_log_mismatch"
    assert result["confidence_recovery"] == 0.0


def test_get_events_by_id(parser, sample_entries):
    """Test get_events_by_id filters by event ID."""
    result = parser.get_events_by_id(sample_entries, 4688)
    assert len(result) == 2
    assert all(e.event_id == 4688 for e in result)


def test_get_timeline_no_filters(parser, sample_entries):
    """Test get_timeline returns sorted entries."""
    result = parser.get_timeline(sample_entries)
    assert len(result) == 3
    assert result[0].record_id == 1001
    assert result[-1].record_id == 1003


def test_get_timeline_with_start_time(parser, sample_entries):
    """Test get_timeline with start time filter."""
    start_time = datetime(2024, 1, 15, 10, 31, 0, tzinfo=timezone.utc)
    result = parser.get_timeline(sample_entries, start_time=start_time)
    assert len(result) == 2
    assert all(e.time_created >= start_time for e in result)


def test_get_timeline_with_end_time(parser, sample_entries):
    """Test get_timeline with end time filter."""
    end_time = datetime(2024, 1, 15, 10, 31, 0, tzinfo=timezone.utc)
    result = parser.get_timeline(sample_entries, end_time=end_time)
    assert len(result) == 2
    assert all(e.time_created <= end_time for e in result)


def test_get_timeline_with_both_filters(parser, sample_entries):
    """Test get_timeline with start and end time filters."""
    start_time = datetime(2024, 1, 15, 10, 30, 30, tzinfo=timezone.utc)
    end_time = datetime(2024, 1, 15, 10, 31, 30, tzinfo=timezone.utc)
    result = parser.get_timeline(
        sample_entries, start_time=start_time, end_time=end_time
    )
    assert len(result) == 1
    assert result[0].record_id == 1002
