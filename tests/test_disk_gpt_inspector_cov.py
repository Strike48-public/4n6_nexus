"""Coverage-focused tests for sift_find_evil.disk.gpt_inspector.

Targets the secondary-entry truncation break (line 300) and the
inspect_ewf pyewf import + handle lifecycle paths (lines 320-335).
These complement tests/test_gpt_inspector.py and do not duplicate it.
"""

import struct
import sys
import uuid
from pathlib import Path
from unittest import mock

import pytest

from sift_find_evil.disk import gpt_inspector
from sift_find_evil.disk.gpt_inspector import (
    SECTOR,
    GPT_HEADER_SIGNATURE,
    GPTInspection,
    inspect_ewf,
    inspect_gpt,
)


def _header_bytes(*, entry_lba: int, entry_count: int, entry_size: int) -> bytes:
    """Build a minimal valid GPT header sector for the given entry array."""
    return struct.pack(
        "<8sIII I QQQQ 16s Q III",
        GPT_HEADER_SIGNATURE,
        0x00010000,  # revision
        92,  # header_size
        0,  # header_crc
        0,  # reserved
        1,  # my_lba
        100,  # alternate_lba
        34,  # first_usable
        99,  # last_usable
        uuid.uuid4().bytes_le,
        entry_lba,
        entry_count,
        entry_size,
        0,  # entries_crc
    ).ljust(SECTOR, b"\x00")


class _TruncatingReader:
    """Reader whose entry-array read returns fewer bytes than requested.

    All sector reads behave normally, but a single oversized read (the
    entry array) is truncated so the per-entry slicing loop hits a chunk
    shorter than MIN_ENTRY_SIZE and breaks.
    """

    def __init__(self, data: bytes, short_read_at: int, truncate_to: int):
        self._data = data
        self._pos = 0
        self._short_read_at = short_read_at
        self._truncate_to = truncate_to

    def seek(self, offset: int) -> int:
        self._pos = offset
        return offset

    def read(self, size: int) -> bytes:
        chunk = self._data[self._pos : self._pos + size]
        if self._pos == self._short_read_at:
            chunk = chunk[: self._truncate_to]
        self._pos += len(chunk)
        return chunk


def test_inspect_gpt_secondary_entry_truncated_breaks():
    """Truncated entry-array read makes the slicing loop break (line 300)."""
    total_sectors = 100
    entry_lba = 2
    entry_count = 4
    entry_size = 128  # array_size = entry_count * entry_size = 512 bytes

    # Bounds must be satisfied so the entry-parsing block executes.
    secondary = _header_bytes(
        entry_lba=entry_lba, entry_count=entry_count, entry_size=entry_size
    )

    disk = bytearray(b"\x00" * (SECTOR * total_sectors))
    # MBR non-zero so it isn't flagged zeroed.
    disk[0:2] = b"\x55\xaa"
    # Secondary header lives at the last sector.
    disk[(total_sectors - 1) * SECTOR : total_sectors * SECTOR] = secondary

    # Lay down one valid entry at the start of the array so we exercise the
    # append path before truncation, then have the read return < entry_size
    # bytes for the trailing chunk.
    type_guid = uuid.uuid4().bytes_le
    unique_guid = uuid.uuid4().bytes_le
    entry0 = struct.pack("<16s 16s QQQ", type_guid, unique_guid, 2048, 4095, 0)
    entry0 = entry0.ljust(entry_size, b"\x00")
    array_off = entry_lba * SECTOR
    disk[array_off : array_off + entry_size] = entry0

    # Truncate the array read to 200 bytes: entry 0 fully present (128),
    # entry 1 chunk is only 72 bytes -> < MIN_ENTRY_SIZE -> break.
    reader = _TruncatingReader(bytes(disk), short_read_at=array_off, truncate_to=200)

    inspection = inspect_gpt(reader, total_sectors)

    assert inspection.secondary_header is not None
    # Only the first (fully-read, valid) entry survives; the loop broke
    # before parsing further truncated chunks.
    assert len(inspection.secondary_entries) == 1
    assert inspection.secondary_entries[0].first_lba == 2048


def test_inspect_ewf_missing_file_raises():
    """inspect_ewf raises FileNotFoundError before touching pyewf (line 318)."""
    with pytest.raises(FileNotFoundError, match="E01 image not found"):
        inspect_ewf(Path("/nonexistent/evidence.E01"))


def test_inspect_ewf_missing_pyewf_raises_importerror(tmp_path, monkeypatch):
    """When pyewf is unavailable the import guard raises ImportError (320-326)."""
    image = tmp_path / "evidence.E01"
    image.write_bytes(b"\x00" * SECTOR)

    # Setting the module entry to None makes `import pyewf` raise ImportError.
    monkeypatch.setitem(sys.modules, "pyewf", None)

    with pytest.raises(ImportError, match="pyewf is required"):
        inspect_ewf(image)


def test_inspect_ewf_uses_pyewf_handle(tmp_path, monkeypatch):
    """inspect_ewf globs, opens, sizes and closes a pyewf handle (328-335)."""
    image = tmp_path / "evidence.E01"
    image.write_bytes(b"\x00" * SECTOR)

    total_sectors = 64

    handle = mock.Mock()
    handle.get_media_size.return_value = total_sectors * SECTOR

    fake_pyewf = mock.Mock()
    fake_pyewf.glob.return_value = ["evidence.E01"]
    fake_pyewf.handle.return_value = handle

    monkeypatch.setitem(sys.modules, "pyewf", fake_pyewf)

    sentinel = GPTInspection(
        total_sectors=total_sectors,
        primary_mbr_zeroed=False,
        primary_header_zeroed=False,
        primary_header=None,
        secondary_header=None,
    )

    captured = {}

    def fake_inspect_gpt(reader, sectors):
        captured["reader"] = reader
        captured["sectors"] = sectors
        return sentinel

    monkeypatch.setattr(gpt_inspector, "inspect_gpt", fake_inspect_gpt)

    result = inspect_ewf(image)

    assert result is sentinel
    fake_pyewf.glob.assert_called_once_with(str(image))
    handle.open.assert_called_once_with(["evidence.E01"])
    handle.close.assert_called_once()
    assert captured["reader"] is handle
    assert captured["sectors"] == total_sectors


def test_inspect_ewf_closes_handle_on_error(tmp_path, monkeypatch):
    """The finally block closes the handle even when inspection raises (335)."""
    image = tmp_path / "evidence.E01"
    image.write_bytes(b"\x00" * SECTOR)

    handle = mock.Mock()
    handle.get_media_size.return_value = 64 * SECTOR

    fake_pyewf = mock.Mock()
    fake_pyewf.glob.return_value = ["evidence.E01"]
    fake_pyewf.handle.return_value = handle

    monkeypatch.setitem(sys.modules, "pyewf", fake_pyewf)

    def boom(reader, sectors):
        raise RuntimeError("parse failure")

    monkeypatch.setattr(gpt_inspector, "inspect_gpt", boom)

    with pytest.raises(RuntimeError, match="parse failure"):
        inspect_ewf(image)

    handle.close.assert_called_once()
