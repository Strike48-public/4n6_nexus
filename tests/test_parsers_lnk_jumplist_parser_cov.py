"""Coverage-focused tests for lnk_jumplist_parser helper/error paths.

Targets previously-uncovered lines:
- _normalize_drive_type: None input guard (169)
- _parse_timestamp: whitespace-only string (180), naive->UTC tz assignment (191)
- _parse_optional_int: whitespace-only string (200), int() ValueError path (203-205)
- LnkParser.parse_csv: csv.Error -> ValueError (329-330)
- JumpListParser.parse_csv: csv.Error -> ValueError (399-400)
"""

from __future__ import annotations

import csv
from datetime import timezone

import pytest

from sift_find_evil.parsers import lnk_jumplist_parser as mod
from sift_find_evil.parsers.lnk_jumplist_parser import (
    JumpListParser,
    LnkParser,
    _normalize_drive_type,
    _parse_optional_int,
    _parse_timestamp,
)


# --- _normalize_drive_type --------------------------------------------------


def test_normalize_drive_type_none_returns_unknown():
    # Line 169: explicit None guard before .strip().lower().
    assert _normalize_drive_type(None) == "unknown"  # type: ignore[arg-type]


# --- _parse_timestamp -------------------------------------------------------


def test_parse_timestamp_whitespace_only_returns_none():
    # Line 180: value is truthy but strips to empty.
    assert _parse_timestamp("   ") is None


def test_parse_timestamp_naive_gets_utc_assigned():
    # Line 191: parsed datetime has no tzinfo, so UTC is attached.
    ts = _parse_timestamp("2026-01-02 03:04:05")
    assert ts is not None
    assert ts.tzinfo == timezone.utc
    assert ts.year == 2026 and ts.hour == 3


def test_parse_timestamp_z_suffix_already_aware_not_reassigned():
    # Companion: aware input keeps its tz, exercising the False branch of 190.
    ts = _parse_timestamp("2026-01-02T03:04:05Z")
    assert ts is not None
    assert ts.utcoffset() == timezone.utc.utcoffset(None)


# --- _parse_optional_int ----------------------------------------------------


def test_parse_optional_int_whitespace_only_returns_none():
    # Line 200: truthy value that strips to empty.
    assert _parse_optional_int("   ") is None


def test_parse_optional_int_non_numeric_returns_none():
    # Lines 203-205: int() raises ValueError -> debug log -> None.
    assert _parse_optional_int("not-a-number") is None


def test_parse_optional_int_valid_value():
    assert _parse_optional_int(" 4096 ") == 4096


# --- csv.Error paths --------------------------------------------------------


class _RaisingReader:
    """DictReader stand-in that raises csv.Error during iteration."""

    def __init__(self, *_args, **_kwargs):
        pass

    def __iter__(self):
        raise csv.Error("simulated malformed CSV")


def _write_csv(tmp_path, name):
    path = tmp_path / name
    path.write_text("SourceFile,TargetPath\nrow,value\n", encoding="utf-8")
    return path


def test_lnk_parser_wraps_csv_error(tmp_path, monkeypatch):
    # Lines 329-330: csv.Error during iteration is wrapped as ValueError.
    monkeypatch.setattr(mod.csv, "DictReader", _RaisingReader)
    csv_path = _write_csv(tmp_path, "lnk.csv")
    with pytest.raises(ValueError, match="Invalid LNK CSV format"):
        LnkParser().parse_csv(csv_path)


def test_jumplist_parser_wraps_csv_error(tmp_path, monkeypatch):
    # Lines 399-400: csv.Error during iteration is wrapped as ValueError.
    monkeypatch.setattr(mod.csv, "DictReader", _RaisingReader)
    csv_path = _write_csv(tmp_path, "jl.csv")
    with pytest.raises(ValueError, match="Invalid Jump List CSV format"):
        JumpListParser().parse_csv(csv_path)
