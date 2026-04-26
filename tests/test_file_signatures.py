"""Tests for file signature detection."""

from sift_find_evil.carving import (
    detect_file_type,
    get_all_signatures,
    get_signatures_by_category,
)


def test_detect_jpeg():
    """Detect JPEG images."""
    data = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01"
    ext, desc = detect_file_type(data)
    assert ext == "jpg"
    assert "JPEG" in desc


def test_detect_png():
    """Detect PNG images."""
    data = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"
    ext, desc = detect_file_type(data)
    assert ext == "png"
    assert "PNG" in desc


def test_detect_pdf():
    """Detect PDF documents."""
    data = b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n"
    ext, desc = detect_file_type(data)
    assert ext == "pdf"
    assert "PDF" in desc


def test_detect_zip():
    """Detect ZIP archives (generic)."""
    data = b"PK\x03\x04\x14\x00\x00\x00\x08\x00" + b"\x00" * 100
    ext, desc = detect_file_type(data)
    assert ext == "zip"
    assert "ZIP" in desc


def test_detect_docx():
    """Detect DOCX documents (ZIP with word/ dir)."""
    data = b"PK\x03\x04" + b"\x00" * 100 + b"word/document.xml"
    ext, desc = detect_file_type(data)
    assert ext == "docx"
    assert "DOCX" in desc


def test_detect_xlsx():
    """Detect XLSX spreadsheets (ZIP with xl/ dir)."""
    data = b"PK\x03\x04" + b"\x00" * 100 + b"xl/workbook.xml"
    ext, desc = detect_file_type(data)
    assert ext == "xlsx"
    assert "XLSX" in desc


def test_detect_pptx():
    """Detect PPTX presentations (ZIP with ppt/ dir)."""
    data = b"PK\x03\x04" + b"\x00" * 100 + b"ppt/presentation.xml"
    ext, desc = detect_file_type(data)
    assert ext == "pptx"
    assert "PPTX" in desc


def test_detect_odt():
    """Detect OpenDocument text (ZIP with mimetype)."""
    data = (
        b"PK\x03\x04" + b"\x00" * 50
        + b"mimetype" + b"\x00" * 20
        + b"application/vnd.oasis.opendocument.text"
    )
    ext, desc = detect_file_type(data)
    assert ext == "odt"
    assert "OpenDocument" in desc


def test_detect_exe():
    """Detect Windows executables."""
    data = b"MZ\x90\x00\x03\x00\x00\x00"
    ext, desc = detect_file_type(data)
    assert ext == "exe"
    assert "PE" in desc or "executable" in desc.lower()


def test_detect_elf():
    """Detect Linux executables."""
    data = b"\x7fELF\x02\x01\x01\x00"
    ext, desc = detect_file_type(data)
    assert ext == "elf"
    assert "ELF" in desc


def test_detect_pst():
    """Detect Outlook PST files."""
    data = b"!BDN" + b"\x00" * 100
    ext, desc = detect_file_type(data)
    assert ext == "pst"
    assert "PST" in desc


def test_detect_sqlite():
    """Detect SQLite databases."""
    data = b"SQLite format 3\x00"
    ext, desc = detect_file_type(data)
    assert ext == "sqlite"
    assert "SQLite" in desc


def test_detect_registry_hive():
    """Detect Windows registry hives."""
    data = b"regf" + b"\x00" * 100
    ext, desc = detect_file_type(data)
    assert ext == "dat"
    assert "registry" in desc.lower()


def test_detect_ntfs_boot():
    """Detect NTFS boot sectors (offset 3)."""
    data = b"\xeb\x52\x90NTFS    \x00\x02"
    ext, desc = detect_file_type(data)
    assert ext == "ntfs"
    assert "NTFS" in desc


def test_detect_avi():
    """Detect AVI video (RIFF with AVI subtype)."""
    data = b"RIFF\x00\x00\x00\x00AVI \x00\x00"
    ext, desc = detect_file_type(data)
    assert ext == "avi"
    assert "AVI" in desc


def test_detect_wav():
    """Detect WAV audio (RIFF with WAVE subtype)."""
    data = b"RIFF\x00\x00\x00\x00WAVE\x00\x00"
    ext, desc = detect_file_type(data)
    assert ext == "wav"
    assert "WAV" in desc


def test_detect_unknown():
    """Unknown signatures return None."""
    data = b"\x00\x00\x00\x00\x00\x00\x00\x00"
    result = detect_file_type(data)
    assert result is None


def test_get_all_signatures():
    """Get all signatures returns non-empty list."""
    sigs = get_all_signatures()
    assert len(sigs) > 0
    assert all(hasattr(sig, "signature") for sig in sigs)
    assert all(hasattr(sig, "extension") for sig in sigs)


def test_get_signatures_by_category():
    """Get signatures by category."""
    images = get_signatures_by_category("images")
    assert len(images) > 0
    assert any("jpg" in sig.extension for sig in images)
    assert any("png" in sig.extension for sig in images)

    docs = get_signatures_by_category("documents")
    assert len(docs) > 0
    assert any("pdf" in sig.extension for sig in docs)

    unknown = get_signatures_by_category("nonexistent")
    assert len(unknown) == 0
