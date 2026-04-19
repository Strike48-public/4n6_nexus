"""Unit tests for the classic .Evt parser (Windows XP / 2003 event logs).

These tests pin two things:

1. Empty logs (header-only file) parse to zero records without exceptions -
   the real m57-jean SecEvent.Evt is in this state and the rest of the
   pipeline must cope.
2. A hand-built record with Event ID 592 (XP process creation) round-trips
   through EventLogEntry and produces the same process-name surface as a
   Vista-era 4688 record would.
"""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from sift_find_evil.parsers.evt_parser import EvtParser
from sift_find_evil.parsers.evtx_parser import EventLogEntry


def _evt_header(start_off: int = 48, end_off: int = 48) -> bytes:
    # 48-byte header: size(4) sig(4) major(4) minor(4) start(4) end(4) curr(4)
    # oldest(4) max_size(4) flags(4) retention(4) end_hdr_size(4)
    return struct.pack(
        "<I4sIIIIIIIIII",
        48,
        b"LfLe",
        1, 1,
        start_off, end_off,
        1, 0,
        65536,
        0, 0, 48,
    )


def _encode_utf16_cstr(s: str) -> bytes:
    return s.encode("utf-16-le") + b"\x00\x00"


def _build_record(
    event_id: int,
    record_number: int,
    time_generated: int,
    source: str,
    computer: str,
    strings: list[str],
) -> bytes:
    source_bytes = _encode_utf16_cstr(source)
    computer_bytes = _encode_utf16_cstr(computer)
    strings_bytes = b"".join(_encode_utf16_cstr(s) for s in strings)

    # record fixed header is 56 bytes up to strings-offset pointer:
    # len(4) magic(4) rec_num(4) time_gen(4) time_wri(4) event_id_full(4)
    # event_type(2) num_strings(2) event_category(2) reserved(2)
    # closing_rec(4) strings_off(4) user_sid_len(4) user_sid_off(4)
    # data_len(4) data_off(4) = 56 bytes
    fixed_header_size = 56
    strings_offset = fixed_header_size + len(source_bytes) + len(computer_bytes)
    record_body = source_bytes + computer_bytes + strings_bytes
    total = fixed_header_size + len(record_body) + 4  # +4 trailing length

    fixed = struct.pack(
        "<I4sIIIIHHHHIIIIII",
        total,
        b"LfLe",
        record_number,
        time_generated,
        time_generated,
        event_id,
        0x0004,  # Information
        len(strings),
        0,
        0,
        0,
        strings_offset,
        0,
        0,
        0,
        0,
    )
    trailing = struct.pack("<I", total)
    return fixed + record_body + trailing


@pytest.mark.unit
def test_empty_evt_parses_to_zero_records(tmp_path: Path) -> None:
    """Real XP default: Security audit off, file is header-only."""
    p = tmp_path / "SecEvent.Evt"
    p.write_bytes(_evt_header(start_off=48, end_off=48))

    parser = EvtParser()
    assert parser.parse_file(p) == []


@pytest.mark.unit
def test_xp_592_maps_to_process_creation(tmp_path: Path) -> None:
    record = _build_record(
        event_id=592,
        record_number=1,
        time_generated=1_216_252_800,  # 2008-07-17 00:00:00 UTC
        source="Security",
        computer="JEANPC",
        strings=[
            "0x4c0",                    # NewProcessId
            "C:\\Program Files\\AIM6\\aim6.exe",  # ImageFileName
            "0x2b0",                    # CreatorProcessId
            "User",                     # TargetUserName
            "JEANPC",                   # TargetDomainName
        ],
    )

    header_size = 48
    start_off = header_size
    end_off = start_off + len(record)

    data = _evt_header(start_off=start_off, end_off=end_off) + record

    p = tmp_path / "SecEvent.Evt"
    p.write_bytes(data)

    entries = EvtParser().parse_file(p)
    assert len(entries) == 1

    entry = entries[0]
    assert isinstance(entry, EventLogEntry)
    assert entry.event_id == 592
    assert entry.is_process_creation()
    assert entry.get_process_name() == "C:\\Program Files\\AIM6\\aim6.exe"
    assert entry.get_executable_name() == "aim6.exe"
    # XP does not ship a command line on 592.
    assert entry.get_command_line() is None


@pytest.mark.unit
def test_4688_still_treated_as_process_creation() -> None:
    """Regression: extending to 592 must not break 4688 handling."""
    from datetime import datetime, timezone

    entry = EventLogEntry(
        time_created=datetime(2026, 1, 1, tzinfo=timezone.utc),
        event_id=4688,
        record_id=1,
        computer="BOX",
        channel="Security",
        level="Information",
        payload_data1="C:\\Windows\\System32\\cmd.exe",
        payload_data6='"cmd.exe" /c whoami',
    )
    assert entry.is_process_creation()
    assert entry.get_process_name() == "C:\\Windows\\System32\\cmd.exe"
    assert entry.get_command_line() == '"cmd.exe" /c whoami'


@pytest.mark.unit
def test_rejects_non_evt_file(tmp_path: Path) -> None:
    bogus = tmp_path / "not_evt.bin"
    bogus.write_bytes(b"NOT_EVT\x00" + b"\x00" * 100)
    with pytest.raises(ValueError, match="Not a classic .Evt"):
        EvtParser().parse_file(bogus)


@pytest.mark.unit
def test_real_jean_evt_fixtures() -> None:
    """Integration-lite: real extracted logs must parse without raising.

    Only runs if artifacts have been extracted. Nothing is asserted about the
    timeline; we just confirm structural compatibility with real-world data.
    """
    base = Path("analysis/m57-jean/extracted/evtlog")
    if not base.exists():
        pytest.skip("Jean artifacts not extracted; run scripts/extract_jean_artifacts.py")

    parser = EvtParser()
    sec = parser.parse_file(base / "SecEvent.Evt")
    app = parser.parse_file(base / "AppEvent.Evt")
    sys_ = parser.parse_file(base / "SysEvent.Evt")

    assert sec == []  # empty security log is a finding in itself
    assert len(app) > 0
    assert len(sys_) > 0
