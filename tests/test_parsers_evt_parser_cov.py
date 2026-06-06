"""Coverage tests for the classic .Evt parser edge/guard paths.

Targets the defensive branches in `EvtParser` and `_from_unix`:
the circular-log revisit guard, zero/oversized record-length stop, the
unparsable-record (entry-is-None) skip, the struct.error guard, the
string-region truncation break, and the user-SID guards (out-of-bounds,
too-short, sub-authority truncation), plus the timestamp overflow fallback.

These complement tests/test_evt_parser.py (happy-path + empty-log).
"""

from __future__ import annotations

import struct
from datetime import datetime, timezone
from pathlib import Path

import pytest

from sift_find_evil.parsers.evt_parser import EvtParser, _from_unix


def _evt_header(start_off: int = 48, end_off: int = 48) -> bytes:
    return struct.pack(
        "<I4sIIIIIIIIII",
        48,
        b"LfLe",
        1,
        1,
        start_off,
        end_off,
        1,
        0,
        65536,
        0,
        0,
        48,
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
    *,
    user_sid: bytes = b"",
    record_length_override: int | None = None,
) -> bytes:
    """Build a classic .Evt record, optionally embedding a user SID blob."""
    source_bytes = _encode_utf16_cstr(source)
    computer_bytes = _encode_utf16_cstr(computer)
    strings_bytes = b"".join(_encode_utf16_cstr(s) for s in strings)

    fixed_header_size = 56
    strings_offset = fixed_header_size + len(source_bytes) + len(computer_bytes)
    sid_offset = strings_offset + len(strings_bytes) if user_sid else 0
    sid_len = len(user_sid)

    record_body = source_bytes + computer_bytes + strings_bytes + user_sid
    total = fixed_header_size + len(record_body) + 4

    length_field = (
        record_length_override if record_length_override is not None else total
    )

    fixed = struct.pack(
        "<I4sIIIIHHHHIIIIII",
        length_field,
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
        sid_len,
        sid_offset,
        0,
        0,
    )
    trailing = struct.pack("<I", total)
    return fixed + record_body + trailing


def _file_with_record(tmp_path: Path, record: bytes) -> Path:
    start_off = 48
    end_off = start_off + len(record)
    data = _evt_header(start_off=start_off, end_off=end_off) + record
    p = tmp_path / "SecEvent.Evt"
    p.write_bytes(data)
    return p


# --- parse_file guard branches --------------------------------------------


@pytest.mark.unit
def test_zero_record_length_stops_iteration(tmp_path: Path) -> None:
    """Line 88-89: a record whose length field is 0 halts the chain."""
    record = _build_record(
        event_id=592,
        record_number=1,
        time_generated=1_216_252_800,
        source="Security",
        computer="BOX",
        strings=["0x1", "C:\\evil.exe"],
        record_length_override=0,
    )
    p = _file_with_record(tmp_path, record)
    # end_off lies past the (now zero-length) record, so the loop enters and
    # immediately breaks on record_length == 0 -> zero entries.
    assert EvtParser().parse_file(p) == []


@pytest.mark.unit
def test_oversized_record_length_stops_iteration(tmp_path: Path) -> None:
    """Line 88-89: record_length larger than the file halts the chain."""
    record = _build_record(
        event_id=592,
        record_number=1,
        time_generated=1_216_252_800,
        source="Security",
        computer="BOX",
        strings=["0x1", "C:\\evil.exe"],
        record_length_override=10_000_000,
    )
    p = _file_with_record(tmp_path, record)
    assert EvtParser().parse_file(p) == []


@pytest.mark.unit
def test_revisited_offset_breaks_loop(tmp_path: Path, monkeypatch) -> None:
    """Line 84: revisiting an already-seen offset breaks the circular walk.

    In a forward walk `off` only increases, so the seen-offset guard is only
    reachable when the circular log loops back onto an earlier record. We
    reproduce that by pre-seeding `seen_offsets` with the start offset: the
    parser constructs its set via the builtin `set()`, so patching
    `builtins.set` to return a pre-seeded subclass forces the very first
    iteration onto the `off in seen_offsets` break.
    """
    valid = _build_record(
        event_id=592,
        record_number=1,
        time_generated=1_216_252_800,
        source="Security",
        computer="BOX",
        strings=["0x1", "C:\\evil.exe"],
    )
    p = _file_with_record(tmp_path, valid)

    import builtins

    start = 48
    real_set = builtins.set

    class _PreSeeded(real_set):
        def __init__(self, *a, **k):
            super().__init__(*a, **k)
            # Only pre-seed empty constructions (the parser's seen_offsets);
            # leave set(iterable) calls untouched.
            if not a:
                real_set.add(self, start)

    monkeypatch.setattr(builtins, "set", _PreSeeded)
    # With start pre-seeded, the first iteration hits `off in seen_offsets`
    # and breaks before parsing -> zero entries.
    assert EvtParser().parse_file(p) == []


@pytest.mark.unit
def test_entry_none_skips_record(tmp_path: Path, monkeypatch) -> None:
    """Lines 95-96: _parse_record returning None advances past the record."""
    rec1 = _build_record(
        event_id=592,
        record_number=1,
        time_generated=1_216_252_800,
        source="Security",
        computer="BOX",
        strings=["0x1", "C:\\one.exe"],
    )
    rec2 = _build_record(
        event_id=592,
        record_number=2,
        time_generated=1_216_252_800,
        source="Security",
        computer="BOX",
        strings=["0x1", "C:\\two.exe"],
    )
    start_off = 48
    body = rec1 + rec2
    data = _evt_header(start_off=start_off, end_off=start_off + len(body)) + body
    p = tmp_path / "SecEvent.Evt"
    p.write_bytes(data)

    real = EvtParser._parse_record
    calls = {"n": 0}

    def fake(self, d, off, rec_len):
        calls["n"] += 1
        if calls["n"] == 1:
            return None  # first record skipped
        return real(self, d, off, rec_len)

    monkeypatch.setattr(EvtParser, "_parse_record", fake)
    entries = EvtParser().parse_file(p)
    # First record skipped via the None branch; second parsed normally.
    assert len(entries) == 1
    assert entries[0].record_id == 2


# --- _parse_record struct.error guard -------------------------------------


@pytest.mark.unit
def test_truncated_record_struct_error_returns_none(tmp_path: Path) -> None:
    """Lines 127-128: a record header too short to unpack returns None.

    Length field passes the > len(data) check and magic matches, but the
    fixed 56-byte header is truncated by EOF, so struct.unpack_from raises
    struct.error and _parse_record returns None.
    """
    start_off = 48
    # 12-byte fragment: valid length (12) + magic + record_number only.
    frag = struct.pack("<I4sI", 12, b"LfLe", 7)
    data = _evt_header(start_off=start_off, end_off=start_off + 64) + frag
    p = tmp_path / "SecEvent.Evt"
    p.write_bytes(data)

    # off+8 < len(data) is satisfied (header 48 + 12 = 60), magic matches at
    # off+4, length 12 <= len(data); unpack of 56 bytes overruns -> struct.error.
    assert EvtParser().parse_file(p) == []


# --- _read_strings truncation break ---------------------------------------


@pytest.mark.unit
def test_read_strings_truncated_region_breaks() -> None:
    """Line 198: cur >= rec_end stops string reads before num_strings done."""
    # num_strings claims 5 but the record body holds none past strings_off.
    data = b"\x00" * 64
    rec_off = 0
    strings_off = 60
    rec_len = 60  # rec_end == rec_off + rec_len == 60 == strings start
    out = EvtParser._read_strings(data, rec_off, strings_off, 5, rec_len)
    assert out == []


@pytest.mark.unit
def test_read_strings_zero_count_returns_empty() -> None:
    """Companion: the num_strings == 0 early return (line 191-192)."""
    assert EvtParser._read_strings(b"\x00" * 64, 0, 10, 0, 60) == []


# --- _read_user_sid guards -------------------------------------------------


@pytest.mark.unit
def test_user_sid_out_of_bounds_returns_none() -> None:
    """Line 216: start + sid_len beyond the buffer returns None."""
    data = b"\x00" * 32
    assert EvtParser._read_user_sid(data, 0, 16, 64) is None


@pytest.mark.unit
def test_user_sid_too_short_returns_none() -> None:
    """Line 219: a SID blob shorter than 8 bytes returns None."""
    data = b"\x01\x00\x00\x00\x00"  # 5 bytes at offset 0
    assert EvtParser._read_user_sid(data, 0, 0, 4) is None
    # sid_off==0 short-circuits; use a non-zero offset to actually reach line 219
    blob = b"\x00\x00\x00\x01\x02\x03\x04"  # 7 bytes
    buf = b"\x00\x00" + blob  # sid at offset 2
    assert EvtParser._read_user_sid(buf, 0, 2, len(blob)) is None


@pytest.mark.unit
def test_user_sid_subauthority_truncation_breaks() -> None:
    """Line 227: sub_count promises more sub-authorities than bytes allow."""
    # revision=1, sub_count=3, authority=5, but only one 4-byte sub follows.
    sid = bytes([1, 3]) + (5).to_bytes(6, "big") + struct.pack("<I", 42)
    # total length 8 + 4 = 12; sub_count 3 needs 12 sub-bytes, only 4 present.
    result = EvtParser._read_user_sid(sid, 0, 0, len(sid))
    # sid_off==0 short-circuits, so call with a real offset/buffer instead.
    buf = b"" + sid
    out = EvtParser._read_user_sid(buf, 0, 0, len(buf))
    assert out is None  # sid_off==0 path
    # Now exercise the truncation break with a valid offset.
    buf2 = b"\xaa\xbb" + sid  # sid begins at offset 2
    out2 = EvtParser._read_user_sid(buf2, 0, 2, len(sid))
    assert out2 is not None
    assert out2.startswith("S-1-5-")
    # Only the one sub-authority that fit (42) is present; the loop broke.
    assert out2 == "S-1-5-42"
    del result


@pytest.mark.unit
def test_user_sid_full_parse_via_record(tmp_path: Path) -> None:
    """End-to-end: a record carrying a well-formed SID populates user_id."""
    # S-1-5-21-1-2-3 : revision 1, sub_count 4, authority 5.
    subs = [21, 1, 2, 3]
    sid = (
        bytes([1, len(subs)])
        + (5).to_bytes(6, "big")
        + b"".join(struct.pack("<I", s) for s in subs)
    )
    record = _build_record(
        event_id=592,
        record_number=9,
        time_generated=1_216_252_800,
        source="Security",
        computer="BOX",
        strings=["0x1", "C:\\evil.exe"],
        user_sid=sid,
    )
    p = _file_with_record(tmp_path, record)
    entries = EvtParser().parse_file(p)
    assert len(entries) == 1
    assert entries[0].user_id == "S-1-5-21-1-2-3"


# --- _from_unix overflow fallback -----------------------------------------


@pytest.mark.unit
def test_from_unix_overflow_returns_epoch_floor() -> None:
    """Lines 235-236: an out-of-range timestamp falls back to 1601-01-01."""
    result = _from_unix(10**30)
    assert result == datetime(1601, 1, 1, tzinfo=timezone.utc)


@pytest.mark.unit
def test_from_unix_negative_returns_epoch_floor() -> None:
    """Negative far-past values also hit the OSError/ValueError fallback."""
    result = _from_unix(-(10**30))
    assert result == datetime(1601, 1, 1, tzinfo=timezone.utc)


@pytest.mark.unit
def test_from_unix_valid_value() -> None:
    """Sanity: an in-range value passes through unchanged (line 234)."""
    result = _from_unix(1_216_252_800)
    assert result == datetime(2008, 7, 17, tzinfo=timezone.utc)
