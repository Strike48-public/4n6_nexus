"""Unit tests for MFT parser."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import pytz

from sift_find_evil.parsers.mft_parser import MFTEntry, MFTParser
from sift_find_evil.validators.timestamp_comparator import TimestampComparator


@pytest.fixture
def parser() -> MFTParser:
    return MFTParser()


@pytest.fixture
def sample_entry() -> MFTEntry:
    """Create a sample MFT entry for testing."""
    return MFTEntry(
        entry_number=123,
        file_name="test.exe",
        parent_path=r"C:\Users\test",
        file_path=r"C:\Users\test\test.exe",
        file_size=1024,
        is_directory=False,
        in_use=True,
        si_created=datetime(2025, 1, 1, 10, 0, tzinfo=timezone.utc),
        si_modified=datetime(2025, 1, 2, 10, 0, tzinfo=timezone.utc),
        si_accessed=datetime(2025, 1, 3, 10, 0, tzinfo=timezone.utc),
        si_mft_modified=datetime(2025, 1, 4, 10, 0, tzinfo=timezone.utc),
        fn_created=datetime(2025, 1, 1, 10, 0, tzinfo=timezone.utc),
        fn_modified=datetime(2025, 1, 2, 10, 0, tzinfo=timezone.utc),
        fn_accessed=datetime(2025, 1, 3, 10, 0, tzinfo=timezone.utc),
        fn_mft_modified=datetime(2025, 1, 4, 10, 0, tzinfo=timezone.utc),
    )


def test_has_timestomping_with_both_timestamps(sample_entry: MFTEntry) -> None:
    """Test has_timestomping when both SI and FN modified timestamps exist."""
    comparator = TimestampComparator()

    # Create entry with timestamp mismatch (potential timestomping)
    entry = MFTEntry(
        entry_number=1,
        file_name="suspicious.exe",
        parent_path=r"C:\Temp",
        file_path=r"C:\Temp\suspicious.exe",
        file_size=1024,
        is_directory=False,
        in_use=True,
        si_created=datetime(2025, 1, 1, 10, 0, tzinfo=timezone.utc),
        si_modified=datetime(2020, 1, 1, 10, 0, tzinfo=timezone.utc),  # Backdated
        si_accessed=datetime(2025, 1, 3, 10, 0, tzinfo=timezone.utc),
        si_mft_modified=datetime(2025, 1, 4, 10, 0, tzinfo=timezone.utc),
        fn_created=datetime(2025, 1, 1, 10, 0, tzinfo=timezone.utc),
        fn_modified=datetime(2025, 1, 2, 10, 0, tzinfo=timezone.utc),  # Recent
        fn_accessed=datetime(2025, 1, 3, 10, 0, tzinfo=timezone.utc),
        fn_mft_modified=datetime(2025, 1, 4, 10, 0, tzinfo=timezone.utc),
    )

    result = entry.has_timestomping(comparator)
    assert result is not None
    # TimestampComparator returns dict with 'severity', 'description', timestamps
    assert "severity" in result


def test_has_timestomping_with_missing_timestamps(sample_entry: MFTEntry) -> None:
    """Test has_timestomping returns None when timestamps are missing."""
    comparator = TimestampComparator()

    # Entry with missing fn_modified
    entry = MFTEntry(
        entry_number=1,
        file_name="test.txt",
        parent_path=r"C:\Temp",
        file_path=r"C:\Temp\test.txt",
        file_size=1024,
        is_directory=False,
        in_use=True,
        si_created=datetime(2025, 1, 1, 10, 0, tzinfo=timezone.utc),
        si_modified=datetime(2025, 1, 2, 10, 0, tzinfo=timezone.utc),
        si_accessed=None,
        si_mft_modified=None,
        fn_created=None,
        fn_modified=None,  # Missing
        fn_accessed=None,
        fn_mft_modified=None,
    )

    result = entry.has_timestomping(comparator)
    assert result is None


def test_get_creation_time_prefer_fn(sample_entry: MFTEntry) -> None:
    """Test get_creation_time prefers FN over SI when prefer_fn=True."""
    result = sample_entry.get_creation_time(prefer_fn=True)
    assert result == sample_entry.fn_created


def test_get_creation_time_prefer_si(sample_entry: MFTEntry) -> None:
    """Test get_creation_time prefers SI over FN when prefer_fn=False."""
    result = sample_entry.get_creation_time(prefer_fn=False)
    assert result == sample_entry.si_created


def test_get_creation_time_fallback(sample_entry: MFTEntry) -> None:
    """Test get_creation_time falls back when preferred timestamp missing."""
    # Entry with only SI created
    entry = MFTEntry(
        entry_number=1,
        file_name="test.txt",
        parent_path=r"C:\Temp",
        file_path=r"C:\Temp\test.txt",
        file_size=1024,
        is_directory=False,
        in_use=True,
        si_created=datetime(2025, 1, 1, 10, 0, tzinfo=timezone.utc),
        si_modified=None,
        si_accessed=None,
        si_mft_modified=None,
        fn_created=None,  # Missing
        fn_modified=None,
        fn_accessed=None,
        fn_mft_modified=None,
    )

    # With prefer_fn=True, should fall back to si_created
    result = entry.get_creation_time(prefer_fn=True)
    assert result == entry.si_created


def test_parse_csv_file_not_found(parser: MFTParser, tmp_path: Path) -> None:
    """Test parse_csv raises FileNotFoundError for missing file."""
    nonexistent = tmp_path / "nonexistent.csv"

    with pytest.raises(FileNotFoundError, match="MFT CSV not found"):
        parser.parse_csv(nonexistent)


def test_parse_csv_invalid_row_skipped(parser: MFTParser, tmp_path: Path) -> None:
    """Test parse_csv skips invalid rows gracefully."""
    csv_file = tmp_path / "invalid.csv"
    csv_file.write_text(
        "EntryNumber,FileName,ParentPath,FileSize,IsDirectory,InUse,Created0x10\n"
        "invalid_number,test.txt,C:\\Temp,1024,False,True,2025-01-01T10:00:00Z\n"  # Invalid entry number
        "2,valid.txt,C:\\Temp,2048,False,True,2025-01-02T10:00:00Z\n",
        encoding="utf-8",
    )

    entries = parser.parse_csv(csv_file)
    # Should skip invalid row and return only the valid one
    assert len(entries) == 1
    assert entries[0].file_name == "valid.txt"


def test_parse_timestamp_with_naive_datetime(parser: MFTParser) -> None:
    """Test _parse_timestamp adds UTC timezone to naive datetimes."""
    # MFTECmd sometimes emits naive timestamps
    result = parser._parse_timestamp("2025-01-01T10:00:00")

    assert result is not None
    assert result.tzinfo is not None
    assert result.tzinfo == pytz.utc


def test_parse_timestamp_null_or_empty(parser: MFTParser) -> None:
    """Test _parse_timestamp handles null/empty strings."""
    assert parser._parse_timestamp(None) is None
    assert parser._parse_timestamp("") is None
    assert parser._parse_timestamp("   ") is None


def test_parse_timestamp_invalid_format(parser: MFTParser) -> None:
    """Test _parse_timestamp handles invalid format gracefully."""
    result = parser._parse_timestamp("not-a-date")
    assert result is None


def test_find_by_filename_case_sensitive(parser: MFTParser) -> None:
    """Test find_by_filename with case-sensitive search."""
    entries = [
        MFTEntry(
            entry_number=1,
            file_name="Test.exe",
            parent_path=r"C:\Temp",
            file_path=r"C:\Temp\Test.exe",
            file_size=1024,
            is_directory=False,
            in_use=True,
            si_created=None,
            si_modified=None,
            si_accessed=None,
            si_mft_modified=None,
            fn_created=None,
            fn_modified=None,
            fn_accessed=None,
            fn_mft_modified=None,
        ),
        MFTEntry(
            entry_number=2,
            file_name="test.exe",
            parent_path=r"C:\Temp",
            file_path=r"C:\Temp\test.exe",
            file_size=2048,
            is_directory=False,
            in_use=True,
            si_created=None,
            si_modified=None,
            si_accessed=None,
            si_mft_modified=None,
            fn_created=None,
            fn_modified=None,
            fn_accessed=None,
            fn_mft_modified=None,
        ),
    ]

    result = parser.find_by_filename(entries, "test.exe", case_sensitive=True)
    assert len(result) == 1
    assert result[0].file_name == "test.exe"


def test_find_by_filename_case_insensitive(parser: MFTParser) -> None:
    """Test find_by_filename with case-insensitive search."""
    entries = [
        MFTEntry(
            entry_number=1,
            file_name="Test.EXE",
            parent_path=r"C:\Temp",
            file_path=r"C:\Temp\Test.EXE",
            file_size=1024,
            is_directory=False,
            in_use=True,
            si_created=None,
            si_modified=None,
            si_accessed=None,
            si_mft_modified=None,
            fn_created=None,
            fn_modified=None,
            fn_accessed=None,
            fn_mft_modified=None,
        ),
        MFTEntry(
            entry_number=2,
            file_name="test.exe",
            parent_path=r"C:\Temp",
            file_path=r"C:\Temp\test.exe",
            file_size=2048,
            is_directory=False,
            in_use=True,
            si_created=None,
            si_modified=None,
            si_accessed=None,
            si_mft_modified=None,
            fn_created=None,
            fn_modified=None,
            fn_accessed=None,
            fn_mft_modified=None,
        ),
    ]

    result = parser.find_by_filename(entries, "test.exe", case_sensitive=False)
    assert len(result) == 2


def test_find_by_path_case_sensitive(parser: MFTParser) -> None:
    """Test find_by_path with case-sensitive search."""
    entries = [
        MFTEntry(
            entry_number=1,
            file_name="test.txt",
            parent_path=r"C:\Temp",
            file_path=r"C:\Temp\test.txt",
            file_size=1024,
            is_directory=False,
            in_use=True,
            si_created=None,
            si_modified=None,
            si_accessed=None,
            si_mft_modified=None,
            fn_created=None,
            fn_modified=None,
            fn_accessed=None,
            fn_mft_modified=None,
        ),
        MFTEntry(
            entry_number=2,
            file_name="test2.txt",
            parent_path=r"C:\temp",
            file_path=r"C:\temp\test2.txt",
            file_size=2048,
            is_directory=False,
            in_use=True,
            si_created=None,
            si_modified=None,
            si_accessed=None,
            si_mft_modified=None,
            fn_created=None,
            fn_modified=None,
            fn_accessed=None,
            fn_mft_modified=None,
        ),
    ]

    result = parser.find_by_path(entries, r"C:\Temp", case_sensitive=True)
    assert len(result) == 1
    assert result[0].file_path == r"C:\Temp\test.txt"


def test_find_by_path_case_insensitive(parser: MFTParser) -> None:
    """Test find_by_path with case-insensitive search."""
    entries = [
        MFTEntry(
            entry_number=1,
            file_name="test.txt",
            parent_path=r"C:\Temp",
            file_path=r"C:\Temp\test.txt",
            file_size=1024,
            is_directory=False,
            in_use=True,
            si_created=None,
            si_modified=None,
            si_accessed=None,
            si_mft_modified=None,
            fn_created=None,
            fn_modified=None,
            fn_accessed=None,
            fn_mft_modified=None,
        ),
        MFTEntry(
            entry_number=2,
            file_name="test2.txt",
            parent_path=r"C:\temp",
            file_path=r"C:\temp\test2.txt",
            file_size=2048,
            is_directory=False,
            in_use=True,
            si_created=None,
            si_modified=None,
            si_accessed=None,
            si_mft_modified=None,
            fn_created=None,
            fn_modified=None,
            fn_accessed=None,
            fn_mft_modified=None,
        ),
    ]

    result = parser.find_by_path(entries, r"C:\Temp", case_sensitive=False)
    assert len(result) == 2


def test_find_timestomped_files(parser: MFTParser) -> None:
    """Test find_timestomped_files detects timestomped entries."""
    entries = [
        MFTEntry(
            entry_number=1,
            file_name="backdated.exe",
            parent_path=r"C:\Temp",
            file_path=r"C:\Temp\backdated.exe",
            file_size=1024,
            is_directory=False,
            in_use=True,
            si_created=datetime(2025, 1, 1, 10, 0, tzinfo=timezone.utc),
            si_modified=datetime(2020, 1, 1, 10, 0, tzinfo=timezone.utc),  # Backdated
            si_accessed=datetime(2025, 1, 3, 10, 0, tzinfo=timezone.utc),
            si_mft_modified=datetime(2025, 1, 4, 10, 0, tzinfo=timezone.utc),
            fn_created=datetime(2025, 1, 1, 10, 0, tzinfo=timezone.utc),
            fn_modified=datetime(2025, 1, 2, 10, 0, tzinfo=timezone.utc),  # Recent
            fn_accessed=datetime(2025, 1, 3, 10, 0, tzinfo=timezone.utc),
            fn_mft_modified=datetime(2025, 1, 4, 10, 0, tzinfo=timezone.utc),
        ),
        MFTEntry(
            entry_number=2,
            file_name="normal.txt",
            parent_path=r"C:\Temp",
            file_path=r"C:\Temp\normal.txt",
            file_size=2048,
            is_directory=False,
            in_use=True,
            si_created=datetime(2025, 1, 1, 10, 0, tzinfo=timezone.utc),
            si_modified=datetime(2025, 1, 2, 10, 0, tzinfo=timezone.utc),
            si_accessed=datetime(2025, 1, 3, 10, 0, tzinfo=timezone.utc),
            si_mft_modified=datetime(2025, 1, 4, 10, 0, tzinfo=timezone.utc),
            fn_created=datetime(2025, 1, 1, 10, 0, tzinfo=timezone.utc),
            fn_modified=datetime(2025, 1, 2, 10, 0, tzinfo=timezone.utc),
            fn_accessed=datetime(2025, 1, 3, 10, 0, tzinfo=timezone.utc),
            fn_mft_modified=datetime(2025, 1, 4, 10, 0, tzinfo=timezone.utc),
        ),
    ]

    result = parser.find_timestomped_files(entries)
    assert len(result) == 1
    entry, details = result[0]
    assert entry.file_name == "backdated.exe"
    assert details is not None


def test_get_recently_modified(parser: MFTParser) -> None:
    """Test get_recently_modified filters by time window."""
    now = datetime.now(pytz.utc)
    recent_time = now - timedelta(hours=1)
    old_time = now - timedelta(hours=48)

    entries = [
        MFTEntry(
            entry_number=1,
            file_name="recent.txt",
            parent_path=r"C:\Temp",
            file_path=r"C:\Temp\recent.txt",
            file_size=1024,
            is_directory=False,
            in_use=True,
            si_created=recent_time,
            si_modified=recent_time,
            si_accessed=recent_time,
            si_mft_modified=recent_time,
            fn_created=recent_time,
            fn_modified=recent_time,
            fn_accessed=recent_time,
            fn_mft_modified=recent_time,
        ),
        MFTEntry(
            entry_number=2,
            file_name="old.txt",
            parent_path=r"C:\Temp",
            file_path=r"C:\Temp\old.txt",
            file_size=2048,
            is_directory=False,
            in_use=True,
            si_created=old_time,
            si_modified=old_time,
            si_accessed=old_time,
            si_mft_modified=old_time,
            fn_created=old_time,
            fn_modified=old_time,
            fn_accessed=old_time,
            fn_mft_modified=old_time,
        ),
    ]

    result = parser.get_recently_modified(entries, within_hours=24)
    assert len(result) == 1
    assert result[0].file_name == "recent.txt"
