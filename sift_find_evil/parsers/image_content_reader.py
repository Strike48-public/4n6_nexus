"""Read file content from forensic disk images via pyewf + pytsk3.

Used by the EXFIL_CORRELATION detector (SFE-3) to compute SHA-256 of on-disk
files for hash-based matching against email attachments. Reads in 4 MB windows
so large files do not exhaust memory.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

import pyewf
import pytsk3

if TYPE_CHECKING:
    from .mft_parser import MFTEntry


class EwfImgInfo(pytsk3.Img_Info):
    """pytsk3 image adapter for pyewf file handles.

    pytsk3 expects a file-like object with read/seek; pyewf provides that via
    its handle. This adapter wires the two together.
    """

    def __init__(self, ewf_handle):
        self._ewf_handle = ewf_handle
        super().__init__(url="", type=pytsk3.TSK_IMG_TYPE_EXTERNAL)

    def close(self):
        self._ewf_handle.close()

    def read(self, offset: int, size: int) -> bytes:
        self._ewf_handle.seek(offset)
        return self._ewf_handle.read(size)

    def get_size(self) -> int:
        return self._ewf_handle.get_media_size()


class ImageContentReader:
    """Read file bytes from an E01 image via MFT entry number.

    Usage:
        reader = ImageContentReader(Path("image.E01"))
        content = reader.read_file(mft_entry)
        reader.close()

    Or use as a context manager:
        with ImageContentReader(Path("image.E01")) as reader:
            content = reader.read_file(mft_entry)
    """

    def __init__(self, image_path: Path):
        """Open an E01 image for reading.

        Args:
            image_path: Path to the .E01 file (split images like .E01/.E02 are
                       auto-discovered by pyewf via the base name).

        Raises:
            FileNotFoundError: If the image file does not exist.
            RuntimeError: If pyewf or pytsk3 fail to open the image.
        """
        if not image_path.exists():
            raise FileNotFoundError(f"Image file not found: {image_path}")

        # pyewf needs a list of segment filenames. For split images (.E01, .E02, ...),
        # pass just the first; pyewf auto-discovers the rest.
        filenames = pyewf.glob(str(image_path))
        if not filenames:
            raise RuntimeError(f"pyewf could not glob image segments: {image_path}")

        self._ewf_handle = pyewf.handle()
        self._ewf_handle.open(filenames)

        # Wrap the EWF handle in a pytsk3 Img_Info adapter
        self._img_info = EwfImgInfo(self._ewf_handle)

        # Auto-detect NTFS partition offset by reading the partition table
        partition_offset = self._find_ntfs_partition()

        # Open the filesystem at the detected offset
        try:
            self._fs = pytsk3.FS_Info(self._img_info, offset=partition_offset)
        except Exception as e:
            self._ewf_handle.close()
            raise RuntimeError(f"Failed to open filesystem at offset {partition_offset}: {e}") from e

    def _find_ntfs_partition(self) -> int:
        """Find the first NTFS partition in the image.

        Returns:
            Byte offset of the NTFS partition.

        Raises:
            RuntimeError: If no NTFS partition is found.
        """
        try:
            vol = pytsk3.Volume_Info(self._img_info)
            for part in vol:
                # NTFS/exFAT has type 0x07
                desc = part.desc.decode() if isinstance(part.desc, bytes) else str(part.desc)
                if "NTFS" in desc or "0x07" in desc:
                    return part.start * 512  # Convert sectors to bytes
        except Exception:
            # No partition table or error — try offset 0 as fallback
            pass

        # Fallback: try offset 0 (single-partition images without partition table)
        return 0

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def close(self):
        """Close the image and release resources."""
        if hasattr(self, "_ewf_handle"):
            self._ewf_handle.close()

    def read_file(self, entry: MFTEntry, window_mb: int = 4) -> bytes:
        """Read the full content of a file given its MFT entry.

        Args:
            entry: MFTEntry with entry_number populated.
            window_mb: Read window size in MB (default 4 MB).

        Returns:
            File bytes as a single concatenated bytestring.

        Raises:
            RuntimeError: If the file cannot be opened or read.
        """
        # pytsk3 identifies files by inode, which is the MFT entry number for NTFS.
        try:
            file_obj = self._fs.open_meta(inode=entry.entry_number)
        except Exception as e:
            raise RuntimeError(
                f"Failed to open MFT entry {entry.entry_number} ({entry.file_name}): {e}"
            ) from e

        # Read the file in chunks to avoid exhausting memory on large files.
        window_bytes = window_mb * 1024 * 1024
        chunks: list[bytes] = []
        offset = 0
        size = file_obj.info.meta.size

        while offset < size:
            read_size = min(window_bytes, size - offset)
            try:
                chunk = file_obj.read_random(offset, read_size)
                if not chunk:
                    break
                chunks.append(chunk)
                offset += len(chunk)
            except Exception as e:
                raise RuntimeError(
                    f"Failed to read from MFT entry {entry.entry_number} at offset {offset}: {e}"
                ) from e

        return b"".join(chunks)


def make_content_reader(image_path: Path):
    """Factory that creates a closure for reading file content.

    Returns a callable that can be passed to MFTParser.parse_csv(content_reader=...).

    Usage:
        reader_factory = make_content_reader(Path("image.E01"))
        entries = mft_parser.parse_csv("mft.csv", content_reader=reader_factory)
        # Each entry now has entry.content_reader(entry) -> bytes

    The returned callable opens the image on first use and caches the handle.
    """
    _reader: ImageContentReader | None = None

    def _read(entry: MFTEntry) -> bytes:
        nonlocal _reader
        if _reader is None:
            _reader = ImageContentReader(image_path)
        return _reader.read_file(entry)

    return _read
