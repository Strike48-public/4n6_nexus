"""Read GPT structures directly from a raw block device, file, or EWF image.

The UEFI 2.9 specification, section 5.3, lays out the GPT header and entry
layout. This module parses just enough of it to recognize a healthy vs wiped
partition table without mutating the evidence.
"""

from __future__ import annotations

import struct
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

SECTOR = 512
GPT_HEADER_SIGNATURE = b"EFI PART"
ZERO_GUID = uuid.UUID(int=0)

# Hard ceilings used when parsing a potentially adversarial image. UEFI 2.9
# requires entry_size >= 128 and entry_count is typically 128 (16 KiB array).
# We cap the allocation at 16 MiB, which is 128x the normal size and still
# comfortably parses any real disk.
MAX_ENTRY_ARRAY_BYTES = 16 * 1024 * 1024
MIN_ENTRY_SIZE = 128
MAX_ENTRIES = 4096


class _Reader(Protocol):
    def seek(self, offset: int) -> int | None: ...
    def read(self, size: int) -> bytes: ...


@dataclass(frozen=True)
class GPTHeader:
    """Fields from a GPT header (UEFI 2.9 Table 21)."""

    signature: bytes
    revision: int
    header_size: int
    header_crc: int
    my_lba: int
    alternate_lba: int
    first_usable_lba: int
    last_usable_lba: int
    disk_guid: uuid.UUID
    entry_lba: int
    entry_count: int
    entry_size: int
    entries_crc: int

    @property
    def is_efi_part(self) -> bool:
        return self.signature == GPT_HEADER_SIGNATURE

    def to_dict(self) -> dict:
        return {
            "signature": self.signature.decode("ascii", errors="replace"),
            "revision": f"0x{self.revision:08x}",
            "header_size": self.header_size,
            "my_lba": self.my_lba,
            "alternate_lba": self.alternate_lba,
            "first_usable_lba": self.first_usable_lba,
            "last_usable_lba": self.last_usable_lba,
            "disk_guid": str(self.disk_guid),
            "entry_lba": self.entry_lba,
            "entry_count": self.entry_count,
            "entry_size": self.entry_size,
        }


@dataclass(frozen=True)
class GPTEntry:
    index: int
    type_guid: uuid.UUID
    unique_guid: uuid.UUID
    first_lba: int
    last_lba: int
    attributes: int
    name: str

    @property
    def size_sectors(self) -> int:
        return self.last_lba - self.first_lba + 1

    @property
    def size_bytes(self) -> int:
        return self.size_sectors * SECTOR

    def to_dict(self) -> dict:
        return {
            "index": self.index,
            "name": self.name,
            "type_guid": str(self.type_guid),
            "unique_guid": str(self.unique_guid),
            "first_lba": self.first_lba,
            "last_lba": self.last_lba,
            "size_sectors": self.size_sectors,
            "size_bytes": self.size_bytes,
        }


@dataclass(frozen=True)
class GPTInspection:
    """Summary of primary vs secondary GPT state on a disk image."""

    total_sectors: int
    primary_mbr_zeroed: bool
    primary_header_zeroed: bool
    primary_header: GPTHeader | None
    secondary_header: GPTHeader | None
    secondary_entries: tuple[GPTEntry, ...] = field(default_factory=tuple)

    @property
    def primary_wiped(self) -> bool:
        """True if no readable primary GPT header is present."""
        return self.primary_header is None

    @property
    def secondary_valid(self) -> bool:
        return self.secondary_header is not None and self.secondary_header.is_efi_part

    def to_dict(self) -> dict:
        return {
            "total_sectors": self.total_sectors,
            "primary_mbr_zeroed": self.primary_mbr_zeroed,
            "primary_header_zeroed": self.primary_header_zeroed,
            "primary_wiped": self.primary_wiped,
            "secondary_valid": self.secondary_valid,
            "primary_header": self.primary_header.to_dict() if self.primary_header else None,
            "secondary_header": self.secondary_header.to_dict() if self.secondary_header else None,
            "secondary_entries": [e.to_dict() for e in self.secondary_entries],
        }


def _parse_header(buf: bytes) -> GPTHeader | None:
    """Return a GPTHeader if buf begins with the EFI signature, else None."""
    if len(buf) < 92 or buf[:8] != GPT_HEADER_SIGNATURE:
        return None

    (
        signature,
        revision,
        header_size,
        header_crc,
        _reserved,
        my_lba,
        alternate_lba,
        first_usable,
        last_usable,
        disk_guid_bytes,
        entry_lba,
        entry_count,
        entry_size,
        entries_crc,
    ) = struct.unpack_from("<8sIII I QQQQ 16s Q III", buf, 0)

    return GPTHeader(
        signature=signature,
        revision=revision,
        header_size=header_size,
        header_crc=header_crc,
        my_lba=my_lba,
        alternate_lba=alternate_lba,
        first_usable_lba=first_usable,
        last_usable_lba=last_usable,
        disk_guid=uuid.UUID(bytes_le=disk_guid_bytes),
        entry_lba=entry_lba,
        entry_count=entry_count,
        entry_size=entry_size,
        entries_crc=entries_crc,
    )


def _parse_entry(index: int, buf: bytes) -> GPTEntry | None:
    if len(buf) < 128:
        return None
    type_guid = uuid.UUID(bytes_le=buf[0:16])
    if type_guid == ZERO_GUID:
        return None
    unique_guid = uuid.UUID(bytes_le=buf[16:32])
    first_lba, last_lba, attributes = struct.unpack_from("<QQQ", buf, 32)
    name = buf[56:128].decode("utf-16-le", errors="replace").rstrip("\x00")
    return GPTEntry(index, type_guid, unique_guid, first_lba, last_lba, attributes, name)


def _read_sector(reader: _Reader, lba: int, total_sectors: int) -> bytes:
    """Read one sector, returning zero-filled bytes for out-of-range LBAs."""
    if lba < 0 or lba >= total_sectors:
        return b"\x00" * SECTOR
    reader.seek(lba * SECTOR)
    data = reader.read(SECTOR)
    if len(data) < SECTOR:
        data = data + b"\x00" * (SECTOR - len(data))
    return data


def _entry_array_bounds_ok(header: GPTHeader, total_sectors: int) -> bool:
    """Return True if reading the entry array described by `header` is safe."""
    if header.entry_size < MIN_ENTRY_SIZE:
        return False
    if header.entry_count <= 0 or header.entry_count > MAX_ENTRIES:
        return False
    array_size = header.entry_count * header.entry_size
    if array_size <= 0 or array_size > MAX_ENTRY_ARRAY_BYTES:
        return False
    if header.entry_lba < 0 or header.entry_lba >= total_sectors:
        return False
    last_byte = header.entry_lba * SECTOR + array_size
    if last_byte > total_sectors * SECTOR:
        return False
    return True


def inspect_gpt(reader: _Reader, total_sectors: int) -> GPTInspection:
    """Inspect GPT on an opened reader. `reader` must provide seek() and read().

    Args:
        reader: object with .seek(offset) and .read(size) (pyewf.handle or BufferedReader).
        total_sectors: total sectors in the logical disk.

    Returns:
        GPTInspection summarising primary vs secondary state and secondary entries.
    """
    if total_sectors < 2:
        return GPTInspection(
            total_sectors=max(total_sectors, 0),
            primary_mbr_zeroed=True,
            primary_header_zeroed=True,
            primary_header=None,
            secondary_header=None,
            secondary_entries=(),
        )

    mbr = _read_sector(reader, 0, total_sectors)
    primary_header_raw = _read_sector(reader, 1, total_sectors)
    secondary_header_raw = _read_sector(reader, total_sectors - 1, total_sectors)

    primary_mbr_zeroed = all(b == 0 for b in mbr)
    primary_header_zeroed = all(b == 0 for b in primary_header_raw)

    primary_header = _parse_header(primary_header_raw)
    secondary_header = _parse_header(secondary_header_raw)

    secondary_entries: list[GPTEntry] = []
    if secondary_header and _entry_array_bounds_ok(secondary_header, total_sectors):
        entry_array_size = secondary_header.entry_count * secondary_header.entry_size
        reader.seek(secondary_header.entry_lba * SECTOR)
        entries_raw = reader.read(entry_array_size)
        for i in range(secondary_header.entry_count):
            start = i * secondary_header.entry_size
            chunk = entries_raw[start : start + secondary_header.entry_size]
            if len(chunk) < MIN_ENTRY_SIZE:
                break
            entry = _parse_entry(i, chunk)
            if entry:
                secondary_entries.append(entry)

    return GPTInspection(
        total_sectors=total_sectors,
        primary_mbr_zeroed=primary_mbr_zeroed,
        primary_header_zeroed=primary_header_zeroed,
        primary_header=primary_header,
        secondary_header=secondary_header,
        secondary_entries=tuple(secondary_entries),
    )


def inspect_ewf(image_path: Path) -> GPTInspection:
    """Convenience wrapper: inspect GPT inside an E01 via pyewf."""
    if not image_path.exists():
        raise FileNotFoundError(f"E01 image not found: {image_path}")

    try:
        import pyewf  # local import so disk tooling is optional
    except ImportError as exc:
        raise ImportError(
            "pyewf is required to read E01 images. Install with: "
            "pip install libewf-python"
        ) from exc

    filenames = pyewf.glob(str(image_path))
    handle = pyewf.handle()
    handle.open(filenames)
    try:
        total_sectors = handle.get_media_size() // SECTOR
        return inspect_gpt(handle, total_sectors)
    finally:
        handle.close()


def inspect_raw(image_path: Path) -> GPTInspection:
    """Convenience wrapper: inspect GPT inside a raw .dd image."""
    if not image_path.exists():
        raise FileNotFoundError(f"Raw image not found: {image_path}")
    size = image_path.stat().st_size
    total_sectors = size // SECTOR
    with image_path.open("rb") as handle:
        return inspect_gpt(handle, total_sectors)
