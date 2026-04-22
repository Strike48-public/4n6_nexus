"""Comprehensive file signature library for carving operations.

Signatures are organized by category with detection offsets and magic bytes.
Used by file carving implementations to identify file types on wiped/unallocated
disk regions.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List


@dataclass(frozen=True)
class FileSignature:
    """A file signature for carving."""

    signature: bytes
    extension: str
    description: str
    offset: int = 0  # Byte offset where signature appears
    footer: bytes | None = None  # Optional EOF marker for complete recovery


# Comprehensive signature library organized by category
SIGNATURES: Dict[str, List[FileSignature]] = {
    "images": [
        FileSignature(b"\xff\xd8\xff\xe0", "jpg", "JPEG/JFIF image"),
        FileSignature(b"\xff\xd8\xff\xe1", "jpg", "JPEG/Exif image"),
        FileSignature(b"\x89PNG\r\n\x1a\n", "png", "PNG image"),
        FileSignature(b"GIF87a", "gif", "GIF image (87a)"),
        FileSignature(b"GIF89a", "gif", "GIF image (89a)"),
        FileSignature(b"BM", "bmp", "Windows bitmap"),
        FileSignature(b"II*\x00", "tif", "TIFF image (little-endian)"),
        FileSignature(b"MM\x00*", "tif", "TIFF image (big-endian)"),
    ],
    "documents": [
        FileSignature(b"%PDF-", "pdf", "PDF document"),
        FileSignature(b"PK\x03\x04", "docx", "DOCX document (check for word/ dir)"),
        FileSignature(b"PK\x03\x04", "xlsx", "XLSX spreadsheet (check for xl/ dir)"),
        FileSignature(b"PK\x03\x04", "pptx", "PPTX presentation (check for ppt/ dir)"),
        FileSignature(b"{\\rtf1", "rtf", "RTF document"),
        FileSignature(b"PK\x03\x04", "odt", "OpenDocument text (check for mimetype)"),
        FileSignature(
            b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "doc", "MS Office 97-2003 document"
        ),
    ],
    "archives": [
        FileSignature(b"PK\x03\x04", "zip", "ZIP archive"),
        FileSignature(b"Rar!\x1a\x07\x00", "rar", "RAR archive (v1.5+)"),
        FileSignature(b"Rar!\x1a\x07\x01\x00", "rar", "RAR archive (v5.0+)"),
        FileSignature(b"7z\xbc\xaf\x27\x1c", "7z", "7-Zip archive"),
        FileSignature(b"\x1f\x8b\x08", "gz", "gzip compressed"),
        FileSignature(b"BZh", "bz2", "bzip2 compressed"),
        FileSignature(b"ustar\x00", "tar", "TAR archive", offset=257),
    ],
    "executables": [
        FileSignature(b"MZ", "exe", "PE/COFF executable (DOS stub)"),
        FileSignature(b"\x7fELF", "elf", "ELF executable"),
        FileSignature(b"\xca\xfe\xba\xbe", "macho", "Mach-O universal binary"),
        FileSignature(b"\xfe\xed\xfa\xce", "macho", "Mach-O 32-bit"),
        FileSignature(b"\xfe\xed\xfa\xcf", "macho", "Mach-O 64-bit"),
    ],
    "email": [
        FileSignature(b"!BDN", "pst", "Outlook PST file"),
        FileSignature(b"From:", "eml", "Email message (RFC 822)"),
        FileSignature(b"Return-Path:", "eml", "Email message"),
        FileSignature(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "msg", "Outlook MSG file"),
    ],
    "databases": [
        FileSignature(b"SQLite format 3", "sqlite", "SQLite database"),
        FileSignature(b"\x00\x01\x00\x00Standard Jet DB", "mdb", "MS Access database"),
        FileSignature(
            b"\x00\x01\x00\x00Standard ACE DB", "accdb", "MS Access 2007+ database"
        ),
    ],
    "windows_artifacts": [
        FileSignature(b"regf", "dat", "Windows registry hive"),
        FileSignature(b"ELF\x1a\x1f\x00\x00", "evtx", "Windows event log"),
        FileSignature(b"SCCA", "pf", "Windows prefetch file", offset=4),
        FileSignature(b"FILE", "mft", "NTFS MFT FILE record"),
        FileSignature(b"BAAD", "mft", "NTFS BAAD record (deleted)"),
        FileSignature(b"INDX", "indx", "NTFS INDX block"),
    ],
    "filesystems": [
        FileSignature(b"NTFS    ", "ntfs", "NTFS boot sector", offset=3),
        FileSignature(b"\x53\xef", "ext", "ext2/ext3/ext4 filesystem", offset=0x438),
        FileSignature(b"LUKS\xba\xbe", "luks", "LUKS encrypted volume"),
    ],
    "multimedia": [
        FileSignature(b"RIFF", "avi", "AVI video (check for AVI subtype)"),
        FileSignature(b"\x00\x00\x00\x20ftyp", "mp4", "MP4 video", offset=4),
        FileSignature(b"ID3", "mp3", "MP3 audio (with ID3 tag)"),
        FileSignature(b"\xff\xfb", "mp3", "MP3 audio (frame sync)"),
        FileSignature(b"OggS", "ogg", "Ogg Vorbis audio"),
    ],
}


def get_all_signatures() -> List[FileSignature]:
    """Get flat list of all signatures for scanning."""
    return [sig for category_sigs in SIGNATURES.values() for sig in category_sigs]


def get_signatures_by_category(category: str) -> List[FileSignature]:
    """Get signatures for a specific category.

    Args:
        category: Category name (images, documents, archives, etc.)

    Returns:
        List of signatures in that category, or empty list if unknown

    Available categories:
        images, documents, archives, executables, email, databases,
        windows_artifacts, filesystems, multimedia
    """
    return SIGNATURES.get(category, [])


def detect_file_type(data: bytes) -> tuple[str, str] | None:
    """Detect file type from header bytes.

    Args:
        data: First N bytes of file (recommend at least 512 bytes)

    Returns:
        Tuple of (extension, description) if match found, else None
    """
    for sig in get_all_signatures():
        if len(data) < sig.offset + len(sig.signature):
            continue

        if data[sig.offset : sig.offset + len(sig.signature)] == sig.signature:
            # Special handling for ambiguous PK\x03\x04 (ZIP-based formats)
            if sig.signature == b"PK\x03\x04":
                # Check internal structure to disambiguate
                if b"word/" in data[:1024]:
                    return ("docx", "DOCX document")
                elif b"xl/" in data[:1024]:
                    return ("xlsx", "XLSX spreadsheet")
                elif b"ppt/" in data[:1024]:
                    return ("pptx", "PPTX presentation")
                elif (
                    b"mimetype" in data[:1024]
                    and b"application/vnd.oasis.opendocument" in data[:1024]
                ):
                    return ("odt", "OpenDocument text")
                else:
                    return ("zip", "ZIP archive")

            # Special handling for RIFF (AVI vs WAV)
            if sig.signature == b"RIFF":
                if b"AVI " in data[8:12]:
                    return ("avi", "AVI video")
                elif b"WAVE" in data[8:12]:
                    return ("wav", "WAV audio")

            return (sig.extension, sig.description)

    return None
