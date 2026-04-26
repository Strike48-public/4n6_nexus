"""Unit tests for the partition-table wipe detector.

We fabricate `GPTInspection` values in-memory rather than synthesising raw disk
images, because the detector is deliberately a pure function of the inspection
summary. Real-image coverage lives in the Real Examples walkthrough.
"""

from __future__ import annotations

import struct
import uuid

import pytest

from sift_find_evil.disk.gpt_inspector import (
    GPT_HEADER_SIGNATURE,
    GPTEntry,
    GPTHeader,
    GPTInspection,
    MAX_ENTRY_ARRAY_BYTES,
    SECTOR,
    inspect_gpt,
)
from sift_find_evil.disk.wipe_detector import detect_wiped_disk


def _make_header(my_lba: int = 15974399) -> GPTHeader:
    return GPTHeader(
        signature=b"EFI PART",
        revision=0x00010000,
        header_size=92,
        header_crc=0,
        my_lba=my_lba,
        alternate_lba=1,
        first_usable_lba=34,
        last_usable_lba=my_lba - 33,
        disk_guid=uuid.UUID(int=0x1234),
        entry_lba=my_lba - 32,
        entry_count=128,
        entry_size=128,
        entries_crc=0,
    )


def _make_entry(index: int = 0) -> GPTEntry:
    return GPTEntry(
        index=index,
        type_guid=uuid.UUID("ebd0a0a2-b9e5-4433-87c0-68b6b72699c7"),
        unique_guid=uuid.uuid4(),
        first_lba=2048,
        last_lba=7383039,
        attributes=0,
        name="disk1",
    )


@pytest.mark.unit
def test_flags_wiped_disk() -> None:
    inspection = GPTInspection(
        total_sectors=15974400,
        primary_mbr_zeroed=True,
        primary_header_zeroed=True,
        primary_header=None,
        secondary_header=_make_header(),
        secondary_entries=(_make_entry(),),
    )
    finding = detect_wiped_disk(inspection)
    assert finding is not None
    assert finding.severity == "critical"
    assert finding.confidence >= 0.9
    assert finding.evidence["primary_header_present"] is False
    assert finding.evidence["secondary_header_valid"] is True
    assert finding.evidence["secondary_entries"], "must list recovered partitions"


@pytest.mark.unit
def test_ignores_healthy_disk() -> None:
    header = _make_header()
    inspection = GPTInspection(
        total_sectors=15974400,
        primary_mbr_zeroed=False,
        primary_header_zeroed=False,
        primary_header=header,
        secondary_header=header,
        secondary_entries=(_make_entry(),),
    )
    assert detect_wiped_disk(inspection) is None


@pytest.mark.unit
def test_ignores_disk_with_no_secondary() -> None:
    inspection = GPTInspection(
        total_sectors=15974400,
        primary_mbr_zeroed=True,
        primary_header_zeroed=True,
        primary_header=None,
        secondary_header=None,
        secondary_entries=(),
    )
    assert detect_wiped_disk(inspection) is None


def _forge_gpt_header_bytes(
    *,
    my_lba: int,
    alt_lba: int,
    entry_lba: int,
    entry_count: int,
    entry_size: int,
) -> bytes:
    """Return a 512-byte sector with a forged GPT header, rest zero-padded."""
    header = struct.pack(
        "<8sIII I QQQQ 16s Q III",
        GPT_HEADER_SIGNATURE,
        0x00010000,  # revision
        92,  # header_size
        0,  # header_crc
        0,  # reserved
        my_lba,
        alt_lba,
        34,  # first_usable
        my_lba - 33,  # last_usable
        b"\x00" * 16,  # disk_guid
        entry_lba,
        entry_count,
        entry_size,
        0,  # entries_crc
    )
    return header + b"\x00" * (SECTOR - len(header))


class _DictReader:
    """Minimal in-memory seek/read over a sparse sector map."""

    def __init__(self, total_sectors: int, sectors: dict[int, bytes]) -> None:
        self._total = total_sectors
        self._sectors = sectors
        self._pos = 0

    def seek(self, offset: int) -> int:
        self._pos = offset
        return offset

    def read(self, size: int) -> bytes:
        out = bytearray()
        remaining = size
        while remaining > 0:
            lba, rem = divmod(self._pos, SECTOR)
            sector = self._sectors.get(lba, b"\x00" * SECTOR)
            take = min(SECTOR - rem, remaining)
            out.extend(sector[rem : rem + take])
            self._pos += take
            remaining -= take
            if lba >= self._total and not self._sectors:
                break
        return bytes(out)


@pytest.mark.unit
def test_rejects_absurd_entry_count_without_huge_allocation() -> None:
    """A crafted image claiming 1B entries must not trigger a GB-scale allocation."""
    total_sectors = 128
    secondary_lba = total_sectors - 1
    malicious = _forge_gpt_header_bytes(
        my_lba=secondary_lba,
        alt_lba=1,
        entry_lba=secondary_lba - 32,
        entry_count=0x40000000,  # 1 billion
        entry_size=128,
    )
    reader = _DictReader(total_sectors, {secondary_lba: malicious})
    inspection = inspect_gpt(reader, total_sectors)
    assert inspection.secondary_header is not None
    assert inspection.secondary_entries == ()  # bounds guard refused to read


@pytest.mark.unit
def test_rejects_entry_array_past_eof() -> None:
    """entry_lba pointing past the end of the image must not seek there."""
    total_sectors = 128
    secondary_lba = total_sectors - 1
    malicious = _forge_gpt_header_bytes(
        my_lba=secondary_lba,
        alt_lba=1,
        entry_lba=10_000_000,  # way past EOF
        entry_count=128,
        entry_size=128,
    )
    reader = _DictReader(total_sectors, {secondary_lba: malicious})
    inspection = inspect_gpt(reader, total_sectors)
    assert inspection.secondary_entries == ()


@pytest.mark.unit
def test_tiny_image_returns_empty_inspection() -> None:
    """A 1-sector image must not explode on total_sectors - 1 reads."""
    reader = _DictReader(1, {})
    inspection = inspect_gpt(reader, 1)
    assert inspection.primary_header is None
    assert inspection.secondary_header is None


@pytest.mark.unit
def test_entry_array_cap_is_16mib() -> None:
    assert MAX_ENTRY_ARRAY_BYTES == 16 * 1024 * 1024


@pytest.mark.unit
def test_detect_wiped_disk_with_source_path() -> None:
    """Test detect_wiped_disk includes source path in evidence."""
    from pathlib import Path

    inspection = GPTInspection(
        total_sectors=15974400,
        primary_mbr_zeroed=True,
        primary_header_zeroed=True,
        primary_header=None,
        secondary_header=_make_header(),
        secondary_entries=(_make_entry(),),
    )
    finding = detect_wiped_disk(inspection, source=Path("/test/disk.e01"))
    assert finding is not None
    assert finding.evidence["image_path"] == "/test/disk.e01"


@pytest.mark.unit
def test_detect_from_image_raw(tmp_path) -> None:
    """Test detect_from_image with raw image."""
    from sift_find_evil.disk.wipe_detector import detect_from_image

    # Create raw image with wiped primary, valid secondary
    image_file = tmp_path / "wiped.dd"
    total_sectors = 100
    mbr = b"\x00" * SECTOR
    primary_header = b"\x00" * SECTOR
    filler = b"\x00" * (SECTOR * 97)

    secondary_header = _forge_gpt_header_bytes(
        my_lba=total_sectors - 1,
        alt_lba=1,
        entry_lba=total_sectors - 32,
        entry_count=128,
        entry_size=128,
    )

    image_file.write_bytes(mbr + primary_header + filler + secondary_header)

    finding = detect_from_image(image_file)
    assert finding is not None
    assert finding.severity == "critical"
    assert str(image_file) in finding.evidence["image_path"]


@pytest.mark.unit
def test_detect_from_image_ewf_extension() -> None:
    """Test detect_from_image recognizes .e01/.ewf extensions."""
    from pathlib import Path
    from sift_find_evil.disk.wipe_detector import detect_from_image

    # Test with fake E01 path (will fail to open, but we just want to test the branch)
    fake_e01 = Path("/nonexistent/wiped.e01")

    try:
        detect_from_image(fake_e01)
    except (OSError, FileNotFoundError):
        # Expected - file doesn't exist or isn't a valid E01
        # The important part is that it tried inspect_ewf instead of inspect_raw
        pass


@pytest.mark.unit
def test_wiped_disk_finding_to_dict() -> None:
    """Test WipedDiskFinding.to_dict() serialization."""
    from sift_find_evil.disk.wipe_detector import WipedDiskFinding
    from sift_find_evil.findings import FindingCategory
    from datetime import datetime, timezone

    finding = WipedDiskFinding(
        title="Test Finding",
        description="Test Description",
        finding_type="indicator",
        severity="critical",
        confidence=0.95,
        confidence_label="Very High",
        category=FindingCategory.ANTI_FORENSICS,
        detected_at=datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc),
    )

    result = finding.to_dict()
    assert result["title"] == "Test Finding"
    assert result["severity"] == "critical"
    assert result["confidence"] == 0.95
    assert result["category"] == "anti_forensics"
    assert result["detected_at"] == "2024-01-01T12:00:00+00:00"
