"""Unit tests for image content reader (SFE-2)."""

from __future__ import annotations

import hashlib
from datetime import datetime

import pytest

from sift_find_evil.parsers.mft_parser import MFTEntry


def test_content_reader_field_on_mft_entry():
    """MFTEntry accepts an optional content_reader callable."""

    def fake_reader(entry: MFTEntry) -> bytes:
        return b"fake content"

    entry = MFTEntry(
        entry_number=42,
        file_name="test.txt",
        parent_path="C:\\Users\\test",
        file_path="C:\\Users\\test\\test.txt",
        file_size=100,
        is_directory=False,
        in_use=True,
        si_created=datetime(2020, 1, 1),
        si_modified=None,
        si_accessed=None,
        si_mft_modified=None,
        fn_created=datetime(2020, 1, 1),
        fn_modified=None,
        fn_accessed=None,
        fn_mft_modified=None,
        content_reader=fake_reader,
    )

    assert entry.content_reader is not None
    assert entry.content_reader(entry) == b"fake content"


def test_content_reader_defaults_to_none():
    """When content_reader is omitted, it defaults to None (CSV-only mode)."""
    entry = MFTEntry(
        entry_number=1,
        file_name="file.txt",
        parent_path="C:\\",
        file_path="C:\\file.txt",
        file_size=0,
        is_directory=False,
        in_use=True,
        si_created=None,
        si_modified=None,
        si_accessed=None,
        si_mft_modified=None,
        fn_created=None,
        fn_modified=None,
        fn_accessed=None,
        fn_mft_modified=None,
    )
    assert entry.content_reader is None


def test_content_reader_computes_sha256():
    """A content reader callable can produce bytes for hash computation.

    This is the acceptance test per SFE-2: fake MFT entry + fake content reader
    produces expected SHA-256. The EXFIL_CORRELATION detector (SFE-3) will do
    exactly this to match on-disk file hashes against email attachment hashes.
    """
    known_content = b"This is the file content on disk."
    expected_hash = hashlib.sha256(known_content).hexdigest()

    def fake_reader(entry: MFTEntry) -> bytes:
        # In production, this would call ImageContentReader.read_file(entry).
        # Here we just return fixed bytes.
        return known_content

    entry = MFTEntry(
        entry_number=100,
        file_name="document.pdf",
        parent_path="C:\\Users\\Alice\\Desktop",
        file_path="C:\\Users\\Alice\\Desktop\\document.pdf",
        file_size=len(known_content),
        is_directory=False,
        in_use=True,
        si_created=datetime(2023, 5, 10),
        si_modified=None,
        si_accessed=None,
        si_mft_modified=None,
        fn_created=datetime(2023, 5, 10),
        fn_modified=None,
        fn_accessed=None,
        fn_mft_modified=None,
        content_reader=fake_reader,
    )

    # Simulate the hash computation the EXFIL_CORRELATION detector will do
    if entry.content_reader is not None:
        content = entry.content_reader(entry)
        computed_hash = hashlib.sha256(content).hexdigest()
        assert computed_hash == expected_hash
