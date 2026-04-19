"""Precise per-sector scan of partition 1 for NTFS / MFT / index / file signatures."""

from __future__ import annotations

from pathlib import Path

import pyewf

SECTOR = 512
E01_PATH = Path("scenarios/real/circl-2023-wiped/evidence/wiped_disk.E01")
PART1_FIRST_LBA = 2048
PART1_LAST_LBA = 7383039


SIGNATURES = {
    b"NTFS    ": "NTFS OEM (in boot sector, at offset 3)",
    b"FILE": "MFT FILE record",
    b"BAAD": "MFT BAAD record",
    b"INDX": "NTFS INDX block",
    b"RSTR": "NTFS logfile restart area",
    b"RCRD": "NTFS logfile record",
    b"\x7fELF": "ELF header",
    b"MZ\x90\x00": "PE/COFF header",
    b"PK\x03\x04": "ZIP/JAR",
    b"%PDF-": "PDF",
    b"\x1f\x8b\x08": "gzip",
}


def main() -> int:
    handle = pyewf.handle()
    handle.open(pyewf.glob(str(E01_PATH)))
    try:
        start = PART1_FIRST_LBA * SECTOR
        end = (PART1_LAST_LBA + 1) * SECTOR

        counts: dict[str, int] = {label: 0 for label in SIGNATURES.values()}
        total_sectors = 0
        nonzero_sectors = 0

        handle.seek(start)
        CHUNK = 4 * 1024 * 1024  # 4 MiB stride for speed
        offset = start
        while offset < end:
            buf = handle.read(min(CHUNK, end - offset))
            if not buf:
                break
            for i in range(0, len(buf), SECTOR):
                sector = buf[i : i + SECTOR]
                total_sectors += 1
                if any(b != 0 for b in sector[:32]):
                    nonzero_sectors += 1
                # Check sector-boundary signatures
                for sig, label in SIGNATURES.items():
                    if sig == b"NTFS    ":
                        if sector[3:11] == sig:
                            counts[label] += 1
                    else:
                        if sector.startswith(sig):
                            counts[label] += 1
            offset += len(buf)

        print(f"Sectors scanned: {total_sectors:,}")
        print(f"Sectors with any non-zero content in first 32 bytes: {nonzero_sectors:,}")
        print(f"Non-zero ratio: {nonzero_sectors / total_sectors:.4%}\n")
        print("Signature hits:")
        for label, c in sorted(counts.items(), key=lambda kv: -kv[1]):
            print(f"  {c:>8}  {label}")
    finally:
        handle.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
