"""Open wiped_disk.E01 and inspect the GPT regions.

Proves the claim from the CIRCL walkthrough:
- LBA 0-33 (primary GPT) is zeroed.
- LBA -1 (secondary GPT header) and LBA -33..-2 (secondary entries) survived.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pyewf

SECTOR = 512
E01_PATH = Path("scenarios/real/circl-2023-wiped/evidence/wiped_disk.E01")


def open_ewf(path: Path) -> pyewf.handle:
    filenames = pyewf.glob(str(path))
    handle = pyewf.handle()
    handle.open(filenames)
    return handle


def dump_sector(handle: pyewf.handle, lba: int, label: str) -> bytes:
    handle.seek(lba * SECTOR)
    data = handle.read(SECTOR)
    nonzero = sum(1 for b in data if b != 0)
    head = data[:64].hex(" ", 1)
    print(f"[LBA {lba:>10}] {label}")
    print(f"  size={len(data)}  nonzero_bytes={nonzero}/{len(data)}")
    print(f"  first 64 bytes: {head}")
    print()
    return data


def main() -> int:
    if not E01_PATH.exists():
        print(f"ERROR: {E01_PATH} missing", file=sys.stderr)
        return 1

    handle = open_ewf(E01_PATH)
    try:
        total_bytes = handle.get_media_size()
        total_sectors = total_bytes // SECTOR
        print(f"Image: {E01_PATH}")
        print(
            f"Logical size: {total_bytes:,} bytes ({total_sectors:,} sectors of {SECTOR} B)\n"
        )

        dump_sector(handle, 0, "Protective MBR / LBA 0")
        dump_sector(handle, 1, "Primary GPT header / LBA 1")
        dump_sector(handle, 2, "Primary GPT entries 1-4 / LBA 2")
        dump_sector(handle, 33, "Primary GPT entries 125-128 / LBA 33")
        dump_sector(handle, total_sectors - 33, "Secondary GPT entries / LBA -33")
        dump_sector(handle, total_sectors - 1, "Secondary GPT header / LBA -1")
    finally:
        handle.close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
