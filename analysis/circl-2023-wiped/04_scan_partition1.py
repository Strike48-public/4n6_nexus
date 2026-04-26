"""Sweep partition 1 looking for NTFS boot sector, $MFT FILE records, and general wipe extent."""

from __future__ import annotations

from pathlib import Path

import pyewf

SECTOR = 512
CHUNK = 1024 * 1024  # 1 MiB scanning stride
E01_PATH = Path("scenarios/real/circl-2023-wiped/evidence/wiped_disk.E01")
PART1_FIRST_LBA = 2048
PART1_LAST_LBA = 7383039


def main() -> int:
    handle = pyewf.handle()
    handle.open(pyewf.glob(str(E01_PATH)))
    try:
        start = PART1_FIRST_LBA * SECTOR
        end = (PART1_LAST_LBA + 1) * SECTOR
        size = end - start
        print(f"Partition 1 span: {start:,} - {end:,} ({size / 1e9:.2f} GB)")

        handle.seek(start)
        zero_bytes = 0
        nonzero_bytes = 0
        first_nonzero_offset: int | None = None
        ntfs_boot_offsets: list[int] = []
        mft_file_offsets: list[int] = []

        offset = start
        zero_chunk = b"\x00" * CHUNK
        while offset < end:
            chunk = handle.read(min(CHUNK, end - offset))
            if not chunk:
                break
            if chunk == zero_chunk:
                zero_bytes += len(chunk)
            else:
                if first_nonzero_offset is None:
                    first_nonzero_offset = offset
                # Count non-zero bytes (sample only - full count is slow)
                nonzero_bytes += sum(1 for b in chunk if b != 0)

                # Look for NTFS OEM signature inside the chunk
                i = chunk.find(b"NTFS    ")
                while i != -1:
                    # NTFS OEM lives at byte offset 3 of the boot sector
                    if i >= 3:
                        ntfs_boot_offsets.append(offset + i - 3)
                    i = chunk.find(b"NTFS    ", i + 1)

                # Look for FILE record signature at sector boundaries
                for sector_start in range(0, len(chunk), SECTOR):
                    if chunk[sector_start : sector_start + 4] == b"FILE":
                        mft_file_offsets.append(offset + sector_start)

            offset += len(chunk)

        print(f"Total zero 1 MiB chunks: {zero_bytes // CHUNK}")
        print(f"First non-zero offset: {first_nonzero_offset!r}")
        if first_nonzero_offset is not None:
            print(
                f"  distance from partition start: {(first_nonzero_offset - start) / 1e6:.2f} MB"
            )
        print(f"NTFS boot sector candidates: {len(ntfs_boot_offsets)}")
        for o in ntfs_boot_offsets[:5]:
            print(f"  - {o:,}  (LBA {o // SECTOR})")
        print(f"MFT 'FILE' record candidates: {len(mft_file_offsets)}")
        for o in mft_file_offsets[:5]:
            print(f"  - {o:,}  (LBA {o // SECTOR})")
    finally:
        handle.close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
