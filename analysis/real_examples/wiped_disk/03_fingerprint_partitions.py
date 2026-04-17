"""Identify the filesystem / container at the start of each partition."""

from __future__ import annotations

from pathlib import Path

import pyewf

SECTOR = 512
E01_PATH = Path("practice_images/wiped_disk.E01")

PARTITIONS = [
    ("Partition 1 (disk1)", 2048, 7383039),
    ("Partition 2 (disk2)", 7383040, 15972351),
]


def main() -> int:
    handle = pyewf.handle()
    handle.open(pyewf.glob(str(E01_PATH)))
    try:
        for label, first, last in PARTITIONS:
            handle.seek(first * SECTOR)
            head = handle.read(512)
            sig = head[:16].hex(" ", 1)
            try:
                ascii_head = head[:64].decode("ascii", errors="replace").replace("\0", ".")
            except Exception:
                ascii_head = "?"
            print(f"{label}: LBA {first}..{last} ({(last - first + 1) * SECTOR / 1e9:.2f} GB)")
            print(f"  first 16 bytes hex : {sig}")
            print(f"  first 64 bytes text: {ascii_head!r}")
            # Identify
            if head[3:11] == b"NTFS    ":
                print("  -> NTFS boot sector (jump + OEM 'NTFS    ')")
            elif head[:6] == b"LUKS\xba\xbe":
                print("  -> LUKS1 header (magic 'LUKS\\xba\\xbe')")
            elif head[:6] == b"LUKS\xba\xbe"[:6]:
                print("  -> LUKS header")
            else:
                # generic
                print("  -> unknown signature")
            print()
    finally:
        handle.close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
