"""Parse the secondary GPT and enumerate partitions.

The primary GPT is wiped. Per UEFI spec, the secondary GPT holds a full copy:
- LBA -1: secondary GPT header (EFI PART signature)
- LBA -33..-2: secondary partition entry array (128 entries, 128 bytes each)

We read header fields per UEFI 2.9 section 5.3, then walk the entry array.
"""

from __future__ import annotations

import struct
import uuid
from dataclasses import dataclass
from pathlib import Path

import pyewf

SECTOR = 512
E01_PATH = Path("scenarios/real/circl-2023-wiped/evidence/wiped_disk.E01")


@dataclass(frozen=True)
class GPTHeader:
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


def parse_header(buf: bytes) -> GPTHeader:
    assert buf[:8] == b"EFI PART", "not a GPT header"
    (
        signature,
        revision,
        header_size,
        header_crc,
        _reserved,
        my_lba,
        alt_lba,
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
        alternate_lba=alt_lba,
        first_usable_lba=first_usable,
        last_usable_lba=last_usable,
        disk_guid=uuid.UUID(bytes_le=disk_guid_bytes),
        entry_lba=entry_lba,
        entry_count=entry_count,
        entry_size=entry_size,
        entries_crc=entries_crc,
    )


def parse_entry(index: int, buf: bytes) -> GPTEntry | None:
    type_guid = uuid.UUID(bytes_le=buf[0:16])
    if type_guid == uuid.UUID(int=0):
        return None
    unique_guid = uuid.UUID(bytes_le=buf[16:32])
    first_lba, last_lba, attrs = struct.unpack_from("<QQQ", buf, 32)
    name = buf[56:128].decode("utf-16-le", errors="replace").rstrip("\x00")
    return GPTEntry(index, type_guid, unique_guid, first_lba, last_lba, attrs, name)


def main() -> int:
    handle = pyewf.handle()
    handle.open(pyewf.glob(str(E01_PATH)))
    try:
        total_sectors = handle.get_media_size() // SECTOR

        handle.seek((total_sectors - 1) * SECTOR)
        header_raw = handle.read(SECTOR)
        header = parse_header(header_raw)

        print(f"Secondary GPT header at LBA {total_sectors - 1}")
        print(f"  signature         : {header.signature!r}")
        print(f"  revision          : 0x{header.revision:08x}")
        print(f"  disk GUID         : {header.disk_guid}")
        print(f"  entry array LBA   : {header.entry_lba}")
        print(f"  entry count       : {header.entry_count}")
        print(f"  entry size        : {header.entry_size}")
        print(f"  first usable LBA  : {header.first_usable_lba}")
        print(f"  last usable LBA   : {header.last_usable_lba}")
        print()

        entries_size = header.entry_count * header.entry_size
        handle.seek(header.entry_lba * SECTOR)
        entries_raw = handle.read(entries_size)

        entries: list[GPTEntry] = []
        for i in range(header.entry_count):
            chunk = entries_raw[i * header.entry_size : (i + 1) * header.entry_size]
            entry = parse_entry(i, chunk)
            if entry:
                entries.append(entry)

        print(f"Populated entries: {len(entries)}")
        for e in entries:
            print()
            print(f"  Entry {e.index + 1}: {e.name!r}")
            print(f"    type GUID     : {e.type_guid}")
            print(f"    unique GUID   : {e.unique_guid}")
            print(f"    first LBA     : {e.first_lba}")
            print(f"    last LBA      : {e.last_lba}")
            print(f"    size          : {e.size_sectors:,} sectors ({e.size_bytes / 1e9:.2f} GB)")
    finally:
        handle.close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
