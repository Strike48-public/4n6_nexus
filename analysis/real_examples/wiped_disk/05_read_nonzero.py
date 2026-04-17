"""Peek at the first non-zero region inside partition 1 to understand what survived."""

from __future__ import annotations

from pathlib import Path

import pyewf

SECTOR = 512
E01_PATH = Path("practice_images/wiped_disk.E01")
# From 04_scan_partition1.py: first non-zero offset inside partition 1
FIRST_NONZERO_OFFSET = 562036736


def main() -> int:
    handle = pyewf.handle()
    handle.open(pyewf.glob(str(E01_PATH)))
    try:
        handle.seek(FIRST_NONZERO_OFFSET)
        data = handle.read(2048)
        print(f"Offset {FIRST_NONZERO_OFFSET:,}:")
        print(data[:512].hex(" ", 1))
        print()
        print("ASCII preview (first 256 printable bytes):")
        printable = "".join(chr(b) if 32 <= b < 127 else "." for b in data[:256])
        print(printable)
    finally:
        handle.close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
