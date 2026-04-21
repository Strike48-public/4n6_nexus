"""Schema-validation tests for CSV parsers (SFE-2lr).

These tests pin the contract that ``parse_csv`` raises ``ValueError`` when the
input CSV header doesn't contain the columns the parser actually reads. The
original behaviour was to silently return empty/default-valued entries, which
masked the SFE-a1w bug: the 06_webmail_exfiltration scenario shipped with
non-canonical column names (``SourceFile``/``ExecutableName``/``LastRun`` and
``ProcessName``/``CommandLine``), and every row parsed into an empty
``PrefetchEntry``/``EventLogEntry``. The resulting "no Prefetch evidence"
state then tripped MISSING_ARTIFACT contradictions on benign browsers and
produced false-positive findings.

The tests cover three axes:
- Well-formed header + zero rows still returns ``[]`` (empty-fixture case).
- Missing or wrong-named required columns raises ``ValueError``.
- A zero-byte file (no header at all) also raises ``ValueError``.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from sift_find_evil.parsers.evtx_parser import EventLogParser
from sift_find_evil.parsers.mft_parser import MFTParser
from sift_find_evil.parsers.prefetch_parser import PrefetchParser


def _write(tmp_path: Path, name: str, content: str) -> Path:
    p = tmp_path / name
    p.write_text(content, encoding="utf-8")
    return p


# ─── PrefetchParser ──────────────────────────────────────────────────────────


def test_prefetch_rejects_csv_missing_executable_column(tmp_path: Path) -> None:
    """The SFE-a1w regression: ``SourceFile``/``ExecutableName``/``LastRun``
    must be rejected, not silently parsed into empty entries."""
    bad = _write(
        tmp_path,
        "prefetch.csv",
        "SourceFile,ExecutableName,RunCount,LastRun\n"
        "C:\\Windows\\Prefetch\\CHROME.EXE-ABCD1234.pf,chrome.exe,15,2025-03-15 10:25:00\n",
    )

    with pytest.raises(ValueError, match="Executable"):
        PrefetchParser().parse_csv(bad)


def test_prefetch_rejects_csv_missing_last_run_time(tmp_path: Path) -> None:
    bad = _write(
        tmp_path,
        "prefetch.csv",
        "SourceFilename,Executable,RunCount\nabc.pf,abc.exe,1\n",
    )

    with pytest.raises(ValueError, match="LastRunTime"):
        PrefetchParser().parse_csv(bad)


def test_prefetch_accepts_header_only_csv(tmp_path: Path) -> None:
    """A well-formed header with zero rows must return ``[]`` without raising."""
    good = _write(
        tmp_path,
        "prefetch.csv",
        "SourceFilename,Executable,RunCount,LastRunTime\n",
    )

    assert PrefetchParser().parse_csv(good) == []


def test_prefetch_rejects_zero_byte_csv(tmp_path: Path) -> None:
    empty = _write(tmp_path, "prefetch.csv", "")

    with pytest.raises(ValueError, match="empty|header"):
        PrefetchParser().parse_csv(empty)


# ─── EventLogParser ──────────────────────────────────────────────────────────


def test_evtx_rejects_csv_missing_time_created(tmp_path: Path) -> None:
    """The other half of the SFE-a1w regression."""
    bad = _write(
        tmp_path,
        "evtx.csv",
        "EventId,Computer,ProcessName,CommandLine\n"
        "4688,DESKTOP-ABC,chrome.exe,C:\\chrome.exe\n",
    )

    with pytest.raises(ValueError, match="TimeCreated"):
        EventLogParser().parse_csv(bad)


def test_evtx_rejects_csv_missing_event_id(tmp_path: Path) -> None:
    bad = _write(
        tmp_path,
        "evtx.csv",
        "TimeCreated,Computer\n2025-03-15T10:25:00Z,DESKTOP-ABC\n",
    )

    with pytest.raises(ValueError, match="EventId"):
        EventLogParser().parse_csv(bad)


def test_evtx_accepts_header_only_csv(tmp_path: Path) -> None:
    good = _write(
        tmp_path,
        "evtx.csv",
        "TimeCreated,EventId,RecordId,Computer,Channel,Level\n",
    )

    assert EventLogParser().parse_csv(good) == []


def test_evtx_rejects_zero_byte_csv(tmp_path: Path) -> None:
    empty = _write(tmp_path, "evtx.csv", "")

    with pytest.raises(ValueError, match="empty|header"):
        EventLogParser().parse_csv(empty)


# ─── MFTParser ───────────────────────────────────────────────────────────────


def test_mft_rejects_csv_missing_filename_column(tmp_path: Path) -> None:
    bad = _write(
        tmp_path,
        "mft.csv",
        "EntryNumber,ParentPath,FileSize,IsDirectory,InUse\n"
        "1,C:\\Windows,0,True,True\n",
    )

    with pytest.raises(ValueError, match="FileName"):
        MFTParser().parse_csv(bad)


def test_mft_accepts_canonical_column_variant_v1(tmp_path: Path) -> None:
    """``Created0x10`` is the current MFTECmd schema."""
    good = _write(
        tmp_path,
        "mft.csv",
        "EntryNumber,FileName,ParentPath,FileSize,IsDirectory,InUse,"
        "Created0x10,Modified0x10,Accessed0x10,Changed0x10,"
        "Created0x30,Modified0x30,Accessed0x30,Changed0x30\n",
    )

    assert MFTParser().parse_csv(good) == []


def test_mft_accepts_canonical_column_variant_v2(tmp_path: Path) -> None:
    """``SI_LtCreated`` is the older MFTECmd schema the parser also supports."""
    good = _write(
        tmp_path,
        "mft.csv",
        "EntryNumber,FileName,ParentPath,FileSize,IsDirectory,InUse,"
        "SI_LtCreated,SI_LtModified,SI_LtAccess,SI_LtMftModified,"
        "FN_LtCreated,FN_LtModified,FN_LtAccess,FN_LtMftModified\n",
    )

    assert MFTParser().parse_csv(good) == []


def test_mft_rejects_zero_byte_csv(tmp_path: Path) -> None:
    empty = _write(tmp_path, "mft.csv", "")

    with pytest.raises(ValueError, match="empty|header"):
        MFTParser().parse_csv(empty)
