"""Unit tests for Registry parser."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from sift_find_evil.parsers.registry_parser import (
    AmcacheEntry,
    BAMEntry,
    RegistryParser,
    RunKeyEntry,
    ShimcacheEntry,
    UserAssistEntry,
)


def test_shimcache_entry_empty_path_raises() -> None:
    """Test ShimcacheEntry raises ValueError for empty file path."""
    with pytest.raises(ValueError, match="File path cannot be empty"):
        ShimcacheEntry(
            file_path="",
            last_modified=datetime(2025, 1, 1, 10, 0, tzinfo=timezone.utc),
            file_size=1024,
        )


def test_amcache_entry_empty_path_raises() -> None:
    """Test AmcacheEntry raises ValueError for empty file path."""
    with pytest.raises(ValueError, match="File path cannot be empty"):
        AmcacheEntry(
            file_path="",
            first_execution=datetime(2025, 1, 1, 10, 0, tzinfo=timezone.utc),
            sha1_hash="a" * 40,
            file_size=1024,
        )


def test_amcache_entry_invalid_sha1_raises() -> None:
    """Test AmcacheEntry raises ValueError for invalid SHA-1 hash."""
    with pytest.raises(
        ValueError, match="SHA-1 hash must be 40 hexadecimal characters"
    ):
        AmcacheEntry(
            file_path=r"C:\test.exe",
            first_execution=datetime(2025, 1, 1, 10, 0, tzinfo=timezone.utc),
            sha1_hash="invalid",
            file_size=1024,
        )


def test_bam_entry_empty_path_raises() -> None:
    """Test BAMEntry raises ValueError for empty file path."""
    with pytest.raises(ValueError, match="File path cannot be empty"):
        BAMEntry(
            file_path="",
            execution_time=datetime(2025, 1, 1, 10, 0, tzinfo=timezone.utc),
            user_sid="S-1-5-21-123",
        )


def test_bam_entry_empty_sid_raises() -> None:
    """Test BAMEntry raises ValueError for empty user SID."""
    with pytest.raises(ValueError, match="User SID cannot be empty"):
        BAMEntry(
            file_path=r"C:\test.exe",
            execution_time=datetime(2025, 1, 1, 10, 0, tzinfo=timezone.utc),
            user_sid="",
        )


def test_userassist_entry_empty_name_raises() -> None:
    """Test UserAssistEntry raises ValueError for empty program name."""
    with pytest.raises(ValueError, match="Program name cannot be empty"):
        UserAssistEntry(
            program_name="",
            run_count=1,
            last_execution=datetime(2025, 1, 1, 10, 0, tzinfo=timezone.utc),
        )


def test_runkey_entry_invalid_hive_raises() -> None:
    """Test RunKeyEntry raises ValueError for invalid hive."""
    with pytest.raises(ValueError, match="Invalid hive"):
        RunKeyEntry(
            key_path=r"Software\Microsoft\Windows\CurrentVersion\Run",
            value_name="Test",
            command="test.exe",
            hive="INVALID",
            last_write_time=datetime(2025, 1, 1, 10, 0, tzinfo=timezone.utc),
        )


def test_runkey_entry_empty_command_raises() -> None:
    """Test RunKeyEntry raises ValueError for empty command."""
    with pytest.raises(ValueError, match="Command cannot be empty"):
        RunKeyEntry(
            key_path=r"Software\Microsoft\Windows\CurrentVersion\Run",
            value_name="Test",
            command="",
            hive="HKLM",
            last_write_time=datetime(2025, 1, 1, 10, 0, tzinfo=timezone.utc),
        )


def test_parse_shimcache_csv_file_not_found() -> None:
    """Test parse_shimcache_csv raises FileNotFoundError for missing file."""
    parser = RegistryParser()
    nonexistent = Path("/nonexistent/shimcache.csv")

    with pytest.raises(FileNotFoundError, match="Shimcache CSV not found"):
        parser.parse_shimcache_csv(nonexistent)


def test_parse_shimcache_csv_invalid_format(tmp_path: Path) -> None:
    """Test parse_shimcache_csv raises ValueError for invalid CSV format."""
    parser = RegistryParser()
    csv_file = tmp_path / "shimcache.csv"
    csv_file.write_text(
        "invalid_column\nvalue\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="Invalid Shimcache CSV format"):
        parser.parse_shimcache_csv(csv_file)


def test_parse_shimcache_csv_naive_timestamps(tmp_path: Path) -> None:
    """Test parse_shimcache_csv handles naive datetime timestamps."""
    parser = RegistryParser()
    csv_file = tmp_path / "shimcache.csv"
    csv_file.write_text(
        "file_path,last_modified,file_size,exec_flag\n"
        r'"C:\test.exe",2025-01-01T10:00:00,1024,True' + "\n",
        encoding="utf-8",
    )

    entries = parser.parse_shimcache_csv(csv_file)
    assert len(entries) == 1
    assert entries[0].last_modified.tzinfo is not None


def test_parse_amcache_csv_file_not_found() -> None:
    """Test parse_amcache_csv raises FileNotFoundError for missing file."""
    parser = RegistryParser()
    nonexistent = Path("/nonexistent/amcache.csv")

    with pytest.raises(FileNotFoundError, match="Amcache CSV not found"):
        parser.parse_amcache_csv(nonexistent)


def test_parse_amcache_csv_invalid_format(tmp_path: Path) -> None:
    """Test parse_amcache_csv raises ValueError for invalid CSV format."""
    parser = RegistryParser()
    csv_file = tmp_path / "amcache.csv"
    csv_file.write_text(
        "invalid_column\nvalue\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="Invalid Amcache CSV format"):
        parser.parse_amcache_csv(csv_file)


def test_parse_amcache_csv_naive_timestamps(tmp_path: Path) -> None:
    """Test parse_amcache_csv handles naive datetime timestamps."""
    parser = RegistryParser()
    csv_file = tmp_path / "amcache.csv"
    csv_file.write_text(
        "file_path,first_execution,sha1_hash,file_size,publisher\n"
        r'"C:\test.exe",2025-01-01T10:00:00,'
        + "a" * 40
        + ',1024,"Test Publisher"'
        + "\n",
        encoding="utf-8",
    )

    entries = parser.parse_amcache_csv(csv_file)
    assert len(entries) == 1
    assert entries[0].first_execution.tzinfo is not None


def test_parse_bam_csv_file_not_found() -> None:
    """Test parse_bam_csv raises FileNotFoundError for missing file."""
    parser = RegistryParser()
    nonexistent = Path("/nonexistent/bam.csv")

    with pytest.raises(FileNotFoundError, match="BAM CSV not found"):
        parser.parse_bam_csv(nonexistent)


def test_parse_bam_csv_invalid_format(tmp_path: Path) -> None:
    """Test parse_bam_csv raises ValueError for invalid CSV format."""
    parser = RegistryParser()
    csv_file = tmp_path / "bam.csv"
    csv_file.write_text(
        "invalid_column\nvalue\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="Invalid BAM CSV format"):
        parser.parse_bam_csv(csv_file)


def test_parse_bam_csv_naive_timestamps(tmp_path: Path) -> None:
    """Test parse_bam_csv handles naive datetime timestamps."""
    parser = RegistryParser()
    csv_file = tmp_path / "bam.csv"
    csv_file.write_text(
        "file_path,execution_time,user_sid\n"
        r'"C:\test.exe",2025-01-01T10:00:00,S-1-5-21-123' + "\n",
        encoding="utf-8",
    )

    entries = parser.parse_bam_csv(csv_file)
    assert len(entries) == 1
    assert entries[0].execution_time.tzinfo is not None


def test_parse_userassist_csv_file_not_found() -> None:
    """Test parse_userassist_csv raises FileNotFoundError for missing file."""
    parser = RegistryParser()
    nonexistent = Path("/nonexistent/userassist.csv")

    with pytest.raises(FileNotFoundError, match="UserAssist CSV not found"):
        parser.parse_userassist_csv(nonexistent)


def test_parse_userassist_csv_invalid_format(tmp_path: Path) -> None:
    """Test parse_userassist_csv raises ValueError for invalid CSV format."""
    parser = RegistryParser()
    csv_file = tmp_path / "userassist.csv"
    csv_file.write_text(
        "invalid_column\nvalue\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="Invalid UserAssist CSV format"):
        parser.parse_userassist_csv(csv_file)


def test_parse_userassist_csv_naive_timestamps(tmp_path: Path) -> None:
    """Test parse_userassist_csv handles naive datetime timestamps."""
    parser = RegistryParser()
    csv_file = tmp_path / "userassist.csv"
    csv_file.write_text(
        "program_name,run_count,last_execution,focus_count,focus_time_ms\n"
        "test.exe,5,2025-01-01T10:00:00,10,5000\n",
        encoding="utf-8",
    )

    entries = parser.parse_userassist_csv(csv_file)
    assert len(entries) == 1
    assert entries[0].last_execution.tzinfo is not None


def test_parse_run_keys_csv_file_not_found() -> None:
    """Test parse_run_keys_csv raises FileNotFoundError for missing file."""
    parser = RegistryParser()
    nonexistent = Path("/nonexistent/runkeys.csv")

    with pytest.raises(FileNotFoundError, match="Run keys CSV not found"):
        parser.parse_run_keys_csv(nonexistent)


def test_parse_run_keys_csv_invalid_format(tmp_path: Path) -> None:
    """Test parse_run_keys_csv raises ValueError for invalid CSV format."""
    parser = RegistryParser()
    csv_file = tmp_path / "runkeys.csv"
    csv_file.write_text(
        "invalid_column\nvalue\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="Invalid Run keys CSV format"):
        parser.parse_run_keys_csv(csv_file)


def test_parse_run_keys_csv_naive_timestamps(tmp_path: Path) -> None:
    """Test parse_run_keys_csv handles naive datetime timestamps."""
    parser = RegistryParser()
    csv_file = tmp_path / "runkeys.csv"
    csv_file.write_text(
        "key_path,value_name,command,hive,last_write_time\n"
        r'"Software\Microsoft\Windows\CurrentVersion\Run",Test,test.exe,HKLM,2025-01-01T10:00:00'
        + "\n",
        encoding="utf-8",
    )

    entries = parser.parse_run_keys_csv(csv_file)
    assert len(entries) == 1
    assert entries[0].last_write_time.tzinfo is not None
