"""Read-only extraction of forensic artifacts from nps-2008-jean.E01.

Writes to analysis/real_examples/nps-2008-jean/extracted/. That directory is
gitignored; nothing carved from the image is committed. The image itself is
opened via pyewf in read-only mode and never mounted on the host.
"""

from __future__ import annotations

import hashlib
import sys
import time
from dataclasses import dataclass
from pathlib import Path

import pyewf
import pytsk3

IMAGE = Path("practice_images/nps-2008-jean.E01")
OUT_ROOT = Path("analysis/real_examples/nps-2008-jean/extracted")
NTFS_PART_OFFSET_SECTORS = 63
SECTOR = 512

# What we pull out, grouped by purpose.
TARGETS: tuple[tuple[str, str], ...] = (
    # NTFS metadata
    ("/$MFT", "ntfs/$MFT"),
    ("/$LogFile", "ntfs/$LogFile"),
    # Registry hives (system scope)
    ("/WINDOWS/system32/config/SOFTWARE", "registry/SOFTWARE"),
    ("/WINDOWS/system32/config/SYSTEM", "registry/SYSTEM"),
    ("/WINDOWS/system32/config/SAM", "registry/SAM"),
    ("/WINDOWS/system32/config/SECURITY", "registry/SECURITY"),
    # Event Logs (XP legacy .Evt format)
    ("/WINDOWS/system32/config/SecEvent.Evt", "evtlog/SecEvent.Evt"),
    ("/WINDOWS/system32/config/AppEvent.Evt", "evtlog/AppEvent.Evt"),
    ("/WINDOWS/system32/config/SysEvent.Evt", "evtlog/SysEvent.Evt"),
    # Jean's per-user hive
    ("/Documents and Settings/Jean/NTUSER.DAT", "registry/Jean_NTUSER.DAT"),
    # Email exfiltration candidates
    (
        "/Documents and Settings/Jean/Local Settings/Application Data/Microsoft/Outlook/outlook.pst",
        "email/outlook.pst",
    ),
    # AIM chat transcripts (alisonm57 is Jean's claimed boss)
    (
        "/Documents and Settings/Jean/My Documents/AIMLogger/m57jean/IM Logs/alisonm57.html",
        "chat/alisonm57.html",
    ),
)

# Whole directories we recurse into.
TARGET_DIRS: tuple[tuple[str, str], ...] = (
    ("/WINDOWS/Prefetch", "prefetch"),
    ("/Documents and Settings/Jean/Recent", "lnk/jean_recent"),
    (
        "/Documents and Settings/Jean/Application Data/Microsoft/Office/Recent",
        "lnk/jean_office_recent",
    ),
)


class EWFImg(pytsk3.Img_Info):
    """Adapter that wraps a pyewf handle for pytsk3."""

    def __init__(self, ewf) -> None:
        """Initialize the adapter with a pyewf handle.

        Args:
            ewf: An opened pyewf handle.
        """
        self._ewf = ewf
        super().__init__(url="", type=pytsk3.TSK_IMG_TYPE_EXTERNAL)

    def read(self, off: int, size: int) -> bytes:
        """Read bytes from the EWF image at a given offset.

        Args:
            off: Byte offset in the image.
            size: Number of bytes to read.

        Returns:
            Bytes read from the image.
        """
        self._ewf.seek(off)
        return self._ewf.read(size)

    def get_size(self) -> int:
        """Get the total size of the EWF image in bytes.

        Returns:
            Total media size in bytes.
        """
        return self._ewf.get_media_size()

    def close(self) -> None:
        """Close the adapter (stub for pytsk3 compatibility)."""
        pass


@dataclass(frozen=True)
class ExtractedFile:
    """Metadata for an extracted file."""
    src: str
    dst: Path
    size: int
    sha256: str


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _extract_file(fs: pytsk3.FS_Info, src: str, dst: Path) -> ExtractedFile | None:
    try:
        node = fs.open(src)
    except OSError:
        print(f"  MISS {src}")
        return None
    if not node.info.meta:
        print(f"  MISS {src} (no meta)")
        return None
    size = node.info.meta.size
    dst.parent.mkdir(parents=True, exist_ok=True)
    offset = 0
    with dst.open("wb") as out:
        while offset < size:
            chunk = node.read_random(offset, min(4 * 1024 * 1024, size - offset))
            if not chunk:
                break
            out.write(chunk)
            offset += len(chunk)
    return ExtractedFile(src=src, dst=dst, size=size, sha256=_sha256(dst))


def _extract_dir(
    fs: pytsk3.FS_Info,
    src_dir: str,
    dst_dir: Path,
    max_files: int = 10_000,
) -> list[ExtractedFile]:
    out: list[ExtractedFile] = []
    try:
        directory = fs.open_dir(src_dir)
    except OSError:
        print(f"  MISS {src_dir}/")
        return out
    for entry in directory:
        if not entry.info.name or not entry.info.meta:
            continue
        name = entry.info.name.name.decode(errors="replace")
        if name in (".", ".."):
            continue
        if entry.info.meta.type != pytsk3.TSK_FS_META_TYPE_REG:
            continue
        src_path = f"{src_dir.rstrip('/')}/{name}"
        dst_path = dst_dir / name
        result = _extract_file(fs, src_path, dst_path)
        if result:
            out.append(result)
        if len(out) >= max_files:
            break
    return out


def _maybe_extract_usnjrnl(fs: pytsk3.FS_Info, dst: Path) -> ExtractedFile | None:
    r"""$UsnJrnl:$J is an ADS on $Extend\$UsnJrnl, not reachable via fs.open()."""
    try:
        usn_dir = fs.open_dir("/$Extend")
    except OSError:
        return None
    for entry in usn_dir:
        if not entry.info.name:
            continue
        name = entry.info.name.name.decode(errors="replace")
        if name != "$UsnJrnl":
            continue
        if not entry.info.meta:
            return None
        node = entry.as_fs_info() if hasattr(entry, "as_fs_info") else None
        # Walk attributes looking for the $J data stream
        f = fs.open_meta(inode=entry.info.meta.addr)
        for attr in f:
            attr_name = attr.info.name.decode(errors="replace") if attr.info.name else ""
            if attr.info.type == pytsk3.TSK_FS_ATTR_TYPE_NTFS_DATA and attr_name == "$J":
                size = attr.info.size
                if size <= 0:
                    return None
                dst.parent.mkdir(parents=True, exist_ok=True)
                offset = 0
                with dst.open("wb") as out:
                    while offset < size:
                        chunk = f.read_random(
                            offset,
                            min(4 * 1024 * 1024, size - offset),
                            attr.info.type,
                            attr.info.id,
                        )
                        if not chunk:
                            break
                        out.write(chunk)
                        offset += len(chunk)
                return ExtractedFile(
                    src="/$Extend/$UsnJrnl:$J",
                    dst=dst,
                    size=size,
                    sha256=_sha256(dst),
                )
    return None


def main() -> int:
    """Extract forensic artifacts from the nps-2008-jean E01 image.

    Returns:
        Exit code (0 = success, 2 = image not found).
    """
    if not IMAGE.exists():
        print(f"ERROR: {IMAGE} not found", file=sys.stderr)
        return 2

    OUT_ROOT.mkdir(parents=True, exist_ok=True)

    start = time.time()
    handle = pyewf.handle()
    handle.open(pyewf.glob(str(IMAGE)))
    try:
        img = EWFImg(handle)
        fs = pytsk3.FS_Info(img, offset=NTFS_PART_OFFSET_SECTORS * SECTOR)

        extracted: list[ExtractedFile] = []

        print("=== single-file targets ===")
        for src, rel in TARGETS:
            dst = OUT_ROOT / rel
            result = _extract_file(fs, src, dst)
            if result:
                extracted.append(result)
                print(f"  OK   {src} -> {rel} ({result.size} bytes)")

        print("=== $UsnJrnl:$J (ADS) ===")
        usn = _maybe_extract_usnjrnl(fs, OUT_ROOT / "ntfs/$UsnJrnl_$J")
        if usn:
            extracted.append(usn)
            print(f"  OK   /$Extend/$UsnJrnl:$J ({usn.size} bytes)")
        else:
            print("  MISS /$Extend/$UsnJrnl:$J (not resident or empty)")

        print("=== directory targets ===")
        for src_dir, rel in TARGET_DIRS:
            dst_dir = OUT_ROOT / rel
            results = _extract_dir(fs, src_dir, dst_dir)
            total = sum(r.size for r in results)
            extracted.extend(results)
            print(f"  OK   {src_dir}/ -> {rel}/ ({len(results)} files, {total} bytes)")

        # Manifest
        manifest = OUT_ROOT / "MANIFEST.tsv"
        with manifest.open("w") as m:
            m.write("sha256\tsize\tsrc\tdst\n")
            for item in extracted:
                m.write(f"{item.sha256}\t{item.size}\t{item.src}\t{item.dst.relative_to(OUT_ROOT)}\n")
        print(f"\nWrote manifest: {manifest} ({len(extracted)} entries)")
        print(f"Elapsed: {time.time() - start:.1f}s")
        return 0
    finally:
        handle.close()


if __name__ == "__main__":
    raise SystemExit(main())
