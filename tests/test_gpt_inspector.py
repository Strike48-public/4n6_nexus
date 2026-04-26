"""Tests for GPT inspector."""

import io
import struct
import uuid
from pathlib import Path
from unittest.mock import Mock

import pytest

from sift_find_evil.disk.gpt_inspector import (
    SECTOR,
    GPT_HEADER_SIGNATURE,
    ZERO_GUID,
    GPTEntry,
    GPTHeader,
    GPTInspection,
    _entry_array_bounds_ok,
    _parse_entry,
    _parse_header,
    _read_sector,
    inspect_gpt,
    inspect_raw,
)


@pytest.fixture
def valid_gpt_header_bytes():
    """Create valid GPT header bytes."""
    disk_guid = uuid.uuid4()
    return struct.pack(
        "<8sIII I QQQQ 16s Q III",
        GPT_HEADER_SIGNATURE,  # signature
        0x00010000,  # revision
        92,  # header_size
        0x12345678,  # header_crc
        0,  # reserved
        1,  # my_lba
        100,  # alternate_lba
        34,  # first_usable
        99,  # last_usable
        disk_guid.bytes_le,  # disk_guid
        2,  # entry_lba
        128,  # entry_count
        128,  # entry_size
        0x87654321,  # entries_crc
    )


@pytest.fixture
def valid_gpt_entry_bytes():
    """Create valid GPT entry bytes."""
    type_guid = uuid.uuid4()
    unique_guid = uuid.uuid4()
    name = "TestPartition"
    name_bytes = name.encode("utf-16-le").ljust(72, b"\x00")

    return struct.pack(
        "<16s 16s QQQ",
        type_guid.bytes_le,
        unique_guid.bytes_le,
        2048,  # first_lba
        4095,  # last_lba
        0,  # attributes
    ) + name_bytes


def test_gpt_header_is_efi_part():
    """Test GPTHeader.is_efi_part property."""
    header = GPTHeader(
        signature=GPT_HEADER_SIGNATURE,
        revision=0x00010000,
        header_size=92,
        header_crc=0,
        my_lba=1,
        alternate_lba=100,
        first_usable_lba=34,
        last_usable_lba=99,
        disk_guid=uuid.uuid4(),
        entry_lba=2,
        entry_count=128,
        entry_size=128,
        entries_crc=0,
    )
    assert header.is_efi_part

    invalid_header = GPTHeader(
        signature=b"INVALID ",
        revision=0x00010000,
        header_size=92,
        header_crc=0,
        my_lba=1,
        alternate_lba=100,
        first_usable_lba=34,
        last_usable_lba=99,
        disk_guid=uuid.uuid4(),
        entry_lba=2,
        entry_count=128,
        entry_size=128,
        entries_crc=0,
    )
    assert not invalid_header.is_efi_part


def test_gpt_header_to_dict():
    """Test GPTHeader.to_dict() serialization."""
    disk_guid = uuid.uuid4()
    header = GPTHeader(
        signature=GPT_HEADER_SIGNATURE,
        revision=0x00010000,
        header_size=92,
        header_crc=0x12345678,
        my_lba=1,
        alternate_lba=100,
        first_usable_lba=34,
        last_usable_lba=99,
        disk_guid=disk_guid,
        entry_lba=2,
        entry_count=128,
        entry_size=128,
        entries_crc=0x87654321,
    )

    result = header.to_dict()
    assert result["signature"] == "EFI PART"
    assert result["revision"] == "0x00010000"
    assert result["header_size"] == 92
    assert result["disk_guid"] == str(disk_guid)


def test_gpt_entry_size_sectors():
    """Test GPTEntry.size_sectors property."""
    entry = GPTEntry(
        index=0,
        type_guid=uuid.uuid4(),
        unique_guid=uuid.uuid4(),
        first_lba=2048,
        last_lba=4095,
        attributes=0,
        name="Test",
    )
    assert entry.size_sectors == 2048  # 4095 - 2048 + 1


def test_gpt_entry_size_bytes():
    """Test GPTEntry.size_bytes property."""
    entry = GPTEntry(
        index=0,
        type_guid=uuid.uuid4(),
        unique_guid=uuid.uuid4(),
        first_lba=2048,
        last_lba=4095,
        attributes=0,
        name="Test",
    )
    assert entry.size_bytes == 2048 * SECTOR


def test_gpt_entry_to_dict():
    """Test GPTEntry.to_dict() serialization."""
    type_guid = uuid.uuid4()
    unique_guid = uuid.uuid4()
    entry = GPTEntry(
        index=0,
        type_guid=type_guid,
        unique_guid=unique_guid,
        first_lba=2048,
        last_lba=4095,
        attributes=0,
        name="TestPartition",
    )

    result = entry.to_dict()
    assert result["index"] == 0
    assert result["name"] == "TestPartition"
    assert result["type_guid"] == str(type_guid)
    assert result["unique_guid"] == str(unique_guid)
    assert result["first_lba"] == 2048
    assert result["last_lba"] == 4095
    assert result["size_sectors"] == 2048
    assert result["size_bytes"] == 2048 * SECTOR


def test_gpt_inspection_primary_wiped():
    """Test GPTInspection.primary_wiped property."""
    inspection = GPTInspection(
        total_sectors=1000,
        primary_mbr_zeroed=True,
        primary_header_zeroed=True,
        primary_header=None,
        secondary_header=None,
    )
    assert inspection.primary_wiped

    inspection_with_header = GPTInspection(
        total_sectors=1000,
        primary_mbr_zeroed=False,
        primary_header_zeroed=False,
        primary_header=Mock(),
        secondary_header=None,
    )
    assert not inspection_with_header.primary_wiped


def test_gpt_inspection_secondary_valid():
    """Test GPTInspection.secondary_valid property."""
    valid_header = Mock()
    valid_header.is_efi_part = True

    inspection = GPTInspection(
        total_sectors=1000,
        primary_mbr_zeroed=True,
        primary_header_zeroed=True,
        primary_header=None,
        secondary_header=valid_header,
    )
    assert inspection.secondary_valid

    invalid_header = Mock()
    invalid_header.is_efi_part = False

    inspection_invalid = GPTInspection(
        total_sectors=1000,
        primary_mbr_zeroed=True,
        primary_header_zeroed=True,
        primary_header=None,
        secondary_header=invalid_header,
    )
    assert not inspection_invalid.secondary_valid


def test_gpt_inspection_to_dict():
    """Test GPTInspection.to_dict() serialization."""
    header = Mock()
    header.to_dict = Mock(return_value={"test": "header"})

    entry = Mock()
    entry.to_dict = Mock(return_value={"test": "entry"})

    inspection = GPTInspection(
        total_sectors=1000,
        primary_mbr_zeroed=True,
        primary_header_zeroed=True,
        primary_header=header,
        secondary_header=header,
        secondary_entries=(entry,),
    )

    result = inspection.to_dict()
    assert result["total_sectors"] == 1000
    assert result["primary_mbr_zeroed"] is True
    assert result["primary_header_zeroed"] is True
    assert result["primary_header"] == {"test": "header"}
    assert result["secondary_header"] == {"test": "header"}
    assert len(result["secondary_entries"]) == 1


def test_parse_header_valid(valid_gpt_header_bytes):
    """Test _parse_header with valid GPT header."""
    header = _parse_header(valid_gpt_header_bytes)
    assert header is not None
    assert header.signature == GPT_HEADER_SIGNATURE
    assert header.revision == 0x00010000
    assert header.entry_count == 128


def test_parse_header_too_short():
    """Test _parse_header with buffer too short."""
    header = _parse_header(b"short")
    assert header is None


def test_parse_header_invalid_signature():
    """Test _parse_header with invalid signature."""
    invalid_bytes = b"INVALID " + b"\x00" * 100
    header = _parse_header(invalid_bytes)
    assert header is None


def test_parse_entry_valid(valid_gpt_entry_bytes):
    """Test _parse_entry with valid entry bytes."""
    entry = _parse_entry(0, valid_gpt_entry_bytes)
    assert entry is not None
    assert entry.index == 0
    assert entry.name == "TestPartition"
    assert entry.first_lba == 2048
    assert entry.last_lba == 4095


def test_parse_entry_too_short():
    """Test _parse_entry with buffer too short."""
    entry = _parse_entry(0, b"short")
    assert entry is None


def test_parse_entry_zero_guid():
    """Test _parse_entry with zero GUID (unused entry)."""
    zero_guid_bytes = ZERO_GUID.bytes_le + b"\x00" * 112
    entry = _parse_entry(0, zero_guid_bytes)
    assert entry is None


def test_read_sector_valid():
    """Test _read_sector reads valid sector."""
    reader = io.BytesIO(b"\x00" * 1024)
    sector = _read_sector(reader, 0, 2)
    assert len(sector) == SECTOR
    assert sector == b"\x00" * SECTOR


def test_read_sector_out_of_range():
    """Test _read_sector returns zeros for out-of-range LBA."""
    reader = io.BytesIO(b"\x00" * 1024)
    sector = _read_sector(reader, 999, 2)
    assert len(sector) == SECTOR
    assert sector == b"\x00" * SECTOR


def test_read_sector_partial_read():
    """Test _read_sector pads partial reads."""
    reader = io.BytesIO(b"A" * 256)  # Only 256 bytes available
    sector = _read_sector(reader, 0, 10)
    assert len(sector) == SECTOR
    assert sector[:256] == b"A" * 256
    assert sector[256:] == b"\x00" * (SECTOR - 256)


def test_entry_array_bounds_ok_valid():
    """Test _entry_array_bounds_ok with valid parameters."""
    header = GPTHeader(
        signature=GPT_HEADER_SIGNATURE,
        revision=0,
        header_size=92,
        header_crc=0,
        my_lba=1,
        alternate_lba=100,
        first_usable_lba=34,
        last_usable_lba=99,
        disk_guid=uuid.uuid4(),
        entry_lba=2,
        entry_count=128,
        entry_size=128,
        entries_crc=0,
    )
    assert _entry_array_bounds_ok(header, 1000)


def test_entry_array_bounds_ok_entry_size_too_small():
    """Test _entry_array_bounds_ok rejects entry_size < 128."""
    header = GPTHeader(
        signature=GPT_HEADER_SIGNATURE,
        revision=0,
        header_size=92,
        header_crc=0,
        my_lba=1,
        alternate_lba=100,
        first_usable_lba=34,
        last_usable_lba=99,
        disk_guid=uuid.uuid4(),
        entry_lba=2,
        entry_count=128,
        entry_size=64,  # Too small
        entries_crc=0,
    )
    assert not _entry_array_bounds_ok(header, 1000)


def test_entry_array_bounds_ok_entry_count_too_large():
    """Test _entry_array_bounds_ok rejects entry_count > 4096."""
    header = GPTHeader(
        signature=GPT_HEADER_SIGNATURE,
        revision=0,
        header_size=92,
        header_crc=0,
        my_lba=1,
        alternate_lba=100,
        first_usable_lba=34,
        last_usable_lba=99,
        disk_guid=uuid.uuid4(),
        entry_lba=2,
        entry_count=5000,  # Too large
        entry_size=128,
        entries_crc=0,
    )
    assert not _entry_array_bounds_ok(header, 10000)


def test_entry_array_bounds_ok_array_size_too_large():
    """Test _entry_array_bounds_ok rejects array_size > 16MB."""
    header = GPTHeader(
        signature=GPT_HEADER_SIGNATURE,
        revision=0,
        header_size=92,
        header_crc=0,
        my_lba=1,
        alternate_lba=100,
        first_usable_lba=34,
        last_usable_lba=99,
        disk_guid=uuid.uuid4(),
        entry_lba=2,
        entry_count=4096,
        entry_size=5000,  # Would create >16MB array
        entries_crc=0,
    )
    assert not _entry_array_bounds_ok(header, 100000)


def test_entry_array_bounds_ok_entry_lba_out_of_range():
    """Test _entry_array_bounds_ok rejects entry_lba >= total_sectors."""
    header = GPTHeader(
        signature=GPT_HEADER_SIGNATURE,
        revision=0,
        header_size=92,
        header_crc=0,
        my_lba=1,
        alternate_lba=100,
        first_usable_lba=34,
        last_usable_lba=99,
        disk_guid=uuid.uuid4(),
        entry_lba=2000,  # Beyond total_sectors
        entry_count=128,
        entry_size=128,
        entries_crc=0,
    )
    assert not _entry_array_bounds_ok(header, 1000)


def test_entry_array_bounds_ok_last_byte_exceeds_disk():
    """Test _entry_array_bounds_ok rejects when array extends beyond disk."""
    header = GPTHeader(
        signature=GPT_HEADER_SIGNATURE,
        revision=0,
        header_size=92,
        header_crc=0,
        my_lba=1,
        alternate_lba=100,
        first_usable_lba=34,
        last_usable_lba=99,
        disk_guid=uuid.uuid4(),
        entry_lba=900,
        entry_count=1000,  # Array would extend beyond disk
        entry_size=1000,
        entries_crc=0,
    )
    assert not _entry_array_bounds_ok(header, 1000)


def test_inspect_gpt_total_sectors_too_small():
    """Test inspect_gpt with total_sectors < 2."""
    reader = io.BytesIO(b"")
    inspection = inspect_gpt(reader, 1)
    assert inspection.total_sectors == 1
    assert inspection.primary_mbr_zeroed
    assert inspection.primary_header_zeroed
    assert inspection.primary_header is None
    assert inspection.secondary_header is None


def test_inspect_gpt_primary_zeroed():
    """Test inspect_gpt detects zeroed primary GPT."""
    reader = io.BytesIO(b"\x00" * (SECTOR * 100))
    inspection = inspect_gpt(reader, 100)
    assert inspection.primary_mbr_zeroed
    assert inspection.primary_header_zeroed
    assert inspection.primary_header is None


def test_inspect_gpt_with_valid_headers(valid_gpt_header_bytes):
    """Test inspect_gpt with valid primary and secondary headers."""
    # Build disk image with valid GPT headers
    # MBR should have non-zero bytes to not be detected as zeroed
    mbr = b"\x55\xAA" + (b"\x00" * (SECTOR - 2))  # Valid MBR signature
    primary_header = valid_gpt_header_bytes.ljust(SECTOR, b"\x00")
    filler = b"\x00" * (SECTOR * 97)
    secondary_header = valid_gpt_header_bytes.ljust(SECTOR, b"\x00")

    disk = mbr + primary_header + filler + secondary_header
    reader = io.BytesIO(disk)

    inspection = inspect_gpt(reader, 100)
    assert not inspection.primary_mbr_zeroed
    assert not inspection.primary_header_zeroed
    assert inspection.primary_header is not None
    assert inspection.secondary_header is not None
    assert inspection.secondary_valid


def test_inspect_raw_file_not_found():
    """Test inspect_raw raises FileNotFoundError."""
    with pytest.raises(FileNotFoundError, match="Raw image not found"):
        inspect_raw(Path("/nonexistent/image.dd"))


def test_inspect_raw_valid_file(tmp_path, valid_gpt_header_bytes):
    """Test inspect_raw with valid raw image file."""
    image_file = tmp_path / "test.dd"
    mbr = b"\x00" * SECTOR
    primary_header = valid_gpt_header_bytes.ljust(SECTOR, b"\x00")
    filler = b"\x00" * (SECTOR * 97)
    secondary_header = valid_gpt_header_bytes.ljust(SECTOR, b"\x00")

    image_file.write_bytes(mbr + primary_header + filler + secondary_header)

    inspection = inspect_raw(image_file)
    assert inspection.total_sectors == 100
    assert inspection.primary_header is not None
    assert inspection.secondary_header is not None
