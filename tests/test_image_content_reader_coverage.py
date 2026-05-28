"""Comprehensive tests for image_content_reader.py to achieve 80%+ coverage.

Missing lines from coverage report: 33-34, 38, 50-51, 59, 86-109, 120-132, 140,
150, 154-155, 171-197, 218-226
"""

from __future__ import annotations

import importlib.util
from datetime import datetime
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

# These tests patch pyewf/pytsk3 as real module attributes; without the native
# forensic libraries installed those names are None and the patches cannot bind.
# Skip the whole module in a core (non-forensic) environment.
pytestmark = pytest.mark.skipif(
    importlib.util.find_spec("pyewf") is None
    or importlib.util.find_spec("pytsk3") is None,
    reason="pyewf/pytsk3 not installed — forensic extras",
)

from sift_find_evil.parsers.image_content_reader import (  # noqa: E402
    ImageContentReader,
    make_content_reader,
)
from sift_find_evil.parsers.mft_parser import MFTEntry  # noqa: E402


def create_test_mft_entry(
    entry_number: int = 100,
    file_name: str = "test.txt",
    file_size: int = 1024,
) -> MFTEntry:
    """Create a test MFT entry for testing."""
    return MFTEntry(
        entry_number=entry_number,
        file_name=file_name,
        parent_path="C:\\test",
        file_path=f"C:\\test\\{file_name}",
        file_size=file_size,
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
    )


# Tests for EwfImgInfo class
# Note: EwfImgInfo inherits from pytsk3.Img_Info (C extension), so we test
# via integration tests in ImageContentReader rather than direct unit tests.


# Tests for ImageContentReader.__init__()


@patch("sift_find_evil.parsers.image_content_reader.pytsk3.FS_Info")
@patch("sift_find_evil.parsers.image_content_reader.pytsk3.Volume_Info")
@patch("sift_find_evil.parsers.image_content_reader.pyewf.handle")
@patch("sift_find_evil.parsers.image_content_reader.pyewf.glob")
def test_image_content_reader_init_raises_file_not_found(
    mock_glob, mock_handle_class, mock_volume, mock_fs
):
    """Test ImageContentReader raises FileNotFoundError for missing image."""
    non_existent_path = Path("/tmp/nonexistent.E01")

    with pytest.raises(FileNotFoundError, match="Image file not found"):
        ImageContentReader(non_existent_path)


@patch("sift_find_evil.parsers.image_content_reader.pytsk3.FS_Info")
@patch("sift_find_evil.parsers.image_content_reader.pytsk3.Volume_Info")
@patch("sift_find_evil.parsers.image_content_reader.pyewf.handle")
@patch("sift_find_evil.parsers.image_content_reader.pyewf.glob")
def test_image_content_reader_init_raises_when_no_segments_found(
    mock_glob, mock_handle_class, mock_volume, mock_fs, tmp_path
):
    """Test ImageContentReader raises RuntimeError when pyewf.glob returns empty."""
    image_path = tmp_path / "test.E01"
    image_path.touch()

    # pyewf.glob returns empty list
    mock_glob.return_value = []

    with pytest.raises(RuntimeError, match="pyewf could not glob image segments"):
        ImageContentReader(image_path)


@patch("sift_find_evil.parsers.image_content_reader.EwfImgInfo")
@patch("sift_find_evil.parsers.image_content_reader.pytsk3.FS_Info")
@patch("sift_find_evil.parsers.image_content_reader.pytsk3.Volume_Info")
@patch("sift_find_evil.parsers.image_content_reader.pyewf.handle")
@patch("sift_find_evil.parsers.image_content_reader.pyewf.glob")
def test_image_content_reader_init_finds_ntfs_partition(
    mock_glob, mock_handle_class, mock_volume, mock_fs, mock_ewf_img_info, tmp_path
):
    """Test ImageContentReader finds NTFS partition via Volume_Info."""
    image_path = tmp_path / "test.E01"
    image_path.touch()

    mock_glob.return_value = [str(image_path)]
    mock_handle = Mock()
    mock_handle_class.return_value = mock_handle

    # Mock partition table with NTFS partition
    mock_part = Mock()
    mock_part.desc = b"NTFS / exFAT (0x07)"
    mock_part.start = 2048  # Start at sector 2048

    mock_vol = Mock()
    mock_vol.__iter__ = Mock(return_value=iter([mock_part]))
    mock_volume.return_value = mock_vol

    ImageContentReader(image_path)

    # Should open filesystem at partition offset (2048 sectors * 512 bytes)
    expected_offset = 2048 * 512
    mock_fs.assert_called_once()
    call_kwargs = mock_fs.call_args.kwargs
    assert call_kwargs["offset"] == expected_offset


@patch("sift_find_evil.parsers.image_content_reader.EwfImgInfo")
@patch("sift_find_evil.parsers.image_content_reader.pytsk3.FS_Info")
@patch("sift_find_evil.parsers.image_content_reader.pytsk3.Volume_Info")
@patch("sift_find_evil.parsers.image_content_reader.pyewf.handle")
@patch("sift_find_evil.parsers.image_content_reader.pyewf.glob")
def test_image_content_reader_init_falls_back_to_offset_zero(
    mock_glob, mock_handle_class, mock_volume, mock_fs, mock_ewf_img_info, tmp_path
):
    """Test ImageContentReader falls back to offset 0 when no partition table."""
    image_path = tmp_path / "test.E01"
    image_path.touch()

    mock_glob.return_value = [str(image_path)]
    mock_handle = Mock()
    mock_handle_class.return_value = mock_handle

    # Volume_Info raises exception (no partition table)
    mock_volume.side_effect = Exception("No partition table")

    ImageContentReader(image_path)

    # Should fall back to offset 0
    mock_fs.assert_called_once()
    call_kwargs = mock_fs.call_args.kwargs
    assert call_kwargs["offset"] == 0


@patch("sift_find_evil.parsers.image_content_reader.EwfImgInfo")
@patch("sift_find_evil.parsers.image_content_reader.pytsk3.FS_Info")
@patch("sift_find_evil.parsers.image_content_reader.pytsk3.Volume_Info")
@patch("sift_find_evil.parsers.image_content_reader.pyewf.handle")
@patch("sift_find_evil.parsers.image_content_reader.pyewf.glob")
def test_image_content_reader_init_closes_handle_on_fs_error(
    mock_glob, mock_handle_class, mock_volume, mock_fs, mock_ewf_img_info, tmp_path
):
    """Test ImageContentReader closes EWF handle if FS_Info fails."""
    image_path = tmp_path / "test.E01"
    image_path.touch()

    mock_glob.return_value = [str(image_path)]
    mock_handle = Mock()
    mock_handle_class.return_value = mock_handle

    mock_volume.side_effect = Exception("No partition table")
    mock_fs.side_effect = Exception("Failed to open filesystem")

    with pytest.raises(RuntimeError, match="Failed to open filesystem"):
        ImageContentReader(image_path)

    # Handle should have been closed
    mock_handle.close.assert_called_once()


@patch("sift_find_evil.parsers.image_content_reader.EwfImgInfo")
@patch("sift_find_evil.parsers.image_content_reader.pytsk3.FS_Info")
@patch("sift_find_evil.parsers.image_content_reader.pytsk3.Volume_Info")
@patch("sift_find_evil.parsers.image_content_reader.pyewf.handle")
@patch("sift_find_evil.parsers.image_content_reader.pyewf.glob")
def test_image_content_reader_init_handles_string_partition_desc(
    mock_glob, mock_handle_class, mock_volume, mock_fs, mock_ewf_img_info, tmp_path
):
    """Test ImageContentReader handles partition desc as string (not bytes)."""
    image_path = tmp_path / "test.E01"
    image_path.touch()

    mock_glob.return_value = [str(image_path)]
    mock_handle = Mock()
    mock_handle_class.return_value = mock_handle

    # Mock partition with string desc (not bytes)
    mock_part = Mock()
    mock_part.desc = "NTFS / exFAT (0x07)"  # String, not bytes
    mock_part.start = 2048

    mock_vol = Mock()
    mock_vol.__iter__ = Mock(return_value=iter([mock_part]))
    mock_volume.return_value = mock_vol

    ImageContentReader(image_path)

    # Should still find the NTFS partition
    expected_offset = 2048 * 512
    call_kwargs = mock_fs.call_args.kwargs
    assert call_kwargs["offset"] == expected_offset


# Tests for ImageContentReader context manager


@patch("sift_find_evil.parsers.image_content_reader.EwfImgInfo")
@patch("sift_find_evil.parsers.image_content_reader.pytsk3.FS_Info")
@patch("sift_find_evil.parsers.image_content_reader.pytsk3.Volume_Info")
@patch("sift_find_evil.parsers.image_content_reader.pyewf.handle")
@patch("sift_find_evil.parsers.image_content_reader.pyewf.glob")
def test_image_content_reader_context_manager_enter(
    mock_glob, mock_handle_class, mock_volume, mock_fs, mock_ewf_img_info, tmp_path
):
    """Test ImageContentReader.__enter__() returns self."""
    image_path = tmp_path / "test.E01"
    image_path.touch()

    mock_glob.return_value = [str(image_path)]
    mock_handle = Mock()
    mock_handle_class.return_value = mock_handle
    mock_volume.side_effect = Exception("No partition")

    reader = ImageContentReader(image_path)

    with reader as ctx_reader:
        assert ctx_reader is reader


@patch("sift_find_evil.parsers.image_content_reader.EwfImgInfo")
@patch("sift_find_evil.parsers.image_content_reader.pytsk3.FS_Info")
@patch("sift_find_evil.parsers.image_content_reader.pytsk3.Volume_Info")
@patch("sift_find_evil.parsers.image_content_reader.pyewf.handle")
@patch("sift_find_evil.parsers.image_content_reader.pyewf.glob")
def test_image_content_reader_context_manager_exit_closes(
    mock_glob, mock_handle_class, mock_volume, mock_fs, mock_ewf_img_info, tmp_path
):
    """Test ImageContentReader.__exit__() calls close()."""
    image_path = tmp_path / "test.E01"
    image_path.touch()

    mock_glob.return_value = [str(image_path)]
    mock_handle = Mock()
    mock_handle_class.return_value = mock_handle
    mock_volume.side_effect = Exception("No partition")

    with ImageContentReader(image_path):
        pass

    # Handle should be closed after context exit
    mock_handle.close.assert_called()


@patch("sift_find_evil.parsers.image_content_reader.EwfImgInfo")
@patch("sift_find_evil.parsers.image_content_reader.pytsk3.FS_Info")
@patch("sift_find_evil.parsers.image_content_reader.pytsk3.Volume_Info")
@patch("sift_find_evil.parsers.image_content_reader.pyewf.handle")
@patch("sift_find_evil.parsers.image_content_reader.pyewf.glob")
def test_image_content_reader_close(
    mock_glob, mock_handle_class, mock_volume, mock_fs, mock_ewf_img_info, tmp_path
):
    """Test ImageContentReader.close() closes EWF handle."""
    image_path = tmp_path / "test.E01"
    image_path.touch()

    mock_glob.return_value = [str(image_path)]
    mock_handle = Mock()
    mock_handle_class.return_value = mock_handle
    mock_volume.side_effect = Exception("No partition")

    reader = ImageContentReader(image_path)
    reader.close()

    mock_handle.close.assert_called_once()


@patch("sift_find_evil.parsers.image_content_reader.EwfImgInfo")
@patch("sift_find_evil.parsers.image_content_reader.pytsk3.FS_Info")
@patch("sift_find_evil.parsers.image_content_reader.pytsk3.Volume_Info")
@patch("sift_find_evil.parsers.image_content_reader.pyewf.handle")
@patch("sift_find_evil.parsers.image_content_reader.pyewf.glob")
def test_image_content_reader_close_handles_missing_handle(
    mock_glob, mock_handle_class, mock_volume, mock_fs, mock_ewf_img_info, tmp_path
):
    """Test ImageContentReader.close() handles missing _ewf_handle gracefully."""
    image_path = tmp_path / "test.E01"
    image_path.touch()

    mock_glob.return_value = [str(image_path)]
    mock_handle = Mock()
    mock_handle_class.return_value = mock_handle
    mock_volume.side_effect = Exception("No partition")

    reader = ImageContentReader(image_path)
    # Simulate missing handle
    delattr(reader, "_ewf_handle")

    # Should not raise exception
    reader.close()


# Tests for ImageContentReader.read_file()


@patch("sift_find_evil.parsers.image_content_reader.EwfImgInfo")
@patch("sift_find_evil.parsers.image_content_reader.pytsk3.FS_Info")
@patch("sift_find_evil.parsers.image_content_reader.pytsk3.Volume_Info")
@patch("sift_find_evil.parsers.image_content_reader.pyewf.handle")
@patch("sift_find_evil.parsers.image_content_reader.pyewf.glob")
def test_image_content_reader_read_file_success(
    mock_glob, mock_handle_class, mock_volume, mock_fs, mock_ewf_img_info, tmp_path
):
    """Test ImageContentReader.read_file() reads file content successfully."""
    image_path = tmp_path / "test.E01"
    image_path.touch()

    mock_glob.return_value = [str(image_path)]
    mock_handle = Mock()
    mock_handle_class.return_value = mock_handle
    mock_volume.side_effect = Exception("No partition")

    # Mock filesystem
    mock_file_obj = Mock()
    mock_file_obj.info.meta.size = 12  # Size of "test content"
    mock_file_obj.read_random.return_value = b"test content"

    mock_filesystem = Mock()
    mock_filesystem.open_meta.return_value = mock_file_obj
    mock_fs.return_value = mock_filesystem

    reader = ImageContentReader(image_path)
    entry = create_test_mft_entry(entry_number=42, file_size=12)

    result = reader.read_file(entry)

    assert result == b"test content"
    mock_filesystem.open_meta.assert_called_once_with(inode=42)
    mock_file_obj.read_random.assert_called_once_with(0, 12)


@patch("sift_find_evil.parsers.image_content_reader.EwfImgInfo")
@patch("sift_find_evil.parsers.image_content_reader.pytsk3.FS_Info")
@patch("sift_find_evil.parsers.image_content_reader.pytsk3.Volume_Info")
@patch("sift_find_evil.parsers.image_content_reader.pyewf.handle")
@patch("sift_find_evil.parsers.image_content_reader.pyewf.glob")
def test_image_content_reader_read_file_raises_on_open_meta_error(
    mock_glob, mock_handle_class, mock_volume, mock_fs, mock_ewf_img_info, tmp_path
):
    """Test ImageContentReader.read_file() raises RuntimeError if open_meta fails."""
    image_path = tmp_path / "test.E01"
    image_path.touch()

    mock_glob.return_value = [str(image_path)]
    mock_handle = Mock()
    mock_handle_class.return_value = mock_handle
    mock_volume.side_effect = Exception("No partition")

    # Mock filesystem that raises error on open_meta
    mock_filesystem = Mock()
    mock_filesystem.open_meta.side_effect = Exception("File not found")
    mock_fs.return_value = mock_filesystem

    reader = ImageContentReader(image_path)
    entry = create_test_mft_entry(entry_number=999, file_name="missing.txt")

    with pytest.raises(RuntimeError, match="Failed to open MFT entry 999"):
        reader.read_file(entry)


@patch("sift_find_evil.parsers.image_content_reader.EwfImgInfo")
@patch("sift_find_evil.parsers.image_content_reader.pytsk3.FS_Info")
@patch("sift_find_evil.parsers.image_content_reader.pytsk3.Volume_Info")
@patch("sift_find_evil.parsers.image_content_reader.pyewf.handle")
@patch("sift_find_evil.parsers.image_content_reader.pyewf.glob")
def test_image_content_reader_read_file_reads_in_chunks(
    mock_glob, mock_handle_class, mock_volume, mock_fs, mock_ewf_img_info, tmp_path
):
    """Test ImageContentReader.read_file() reads large files in chunks."""
    image_path = tmp_path / "test.E01"
    image_path.touch()

    mock_glob.return_value = [str(image_path)]
    mock_handle = Mock()
    mock_handle_class.return_value = mock_handle
    mock_volume.side_effect = Exception("No partition")

    # Mock file object with 10 MB size (requires 3 chunks with 4 MB window)
    file_size = 10 * 1024 * 1024  # 10 MB
    chunk1 = b"a" * (4 * 1024 * 1024)  # 4 MB
    chunk2 = b"b" * (4 * 1024 * 1024)  # 4 MB
    chunk3 = b"c" * (2 * 1024 * 1024)  # 2 MB

    mock_file_obj = Mock()
    mock_file_obj.info.meta.size = file_size
    mock_file_obj.read_random.side_effect = [chunk1, chunk2, chunk3]

    mock_filesystem = Mock()
    mock_filesystem.open_meta.return_value = mock_file_obj
    mock_fs.return_value = mock_filesystem

    reader = ImageContentReader(image_path)
    entry = create_test_mft_entry(file_size=file_size)

    result = reader.read_file(entry, window_mb=4)

    assert len(result) == file_size
    assert result[: len(chunk1)] == chunk1
    assert result[len(chunk1) : len(chunk1) + len(chunk2)] == chunk2
    assert result[len(chunk1) + len(chunk2) :] == chunk3

    # Should have called read_random 3 times
    assert mock_file_obj.read_random.call_count == 3


@patch("sift_find_evil.parsers.image_content_reader.EwfImgInfo")
@patch("sift_find_evil.parsers.image_content_reader.pytsk3.FS_Info")
@patch("sift_find_evil.parsers.image_content_reader.pytsk3.Volume_Info")
@patch("sift_find_evil.parsers.image_content_reader.pyewf.handle")
@patch("sift_find_evil.parsers.image_content_reader.pyewf.glob")
def test_image_content_reader_read_file_handles_empty_chunk(
    mock_glob, mock_handle_class, mock_volume, mock_fs, mock_ewf_img_info, tmp_path
):
    """Test ImageContentReader.read_file() stops on empty chunk."""
    image_path = tmp_path / "test.E01"
    image_path.touch()

    mock_glob.return_value = [str(image_path)]
    mock_handle = Mock()
    mock_handle_class.return_value = mock_handle
    mock_volume.side_effect = Exception("No partition")

    # Mock file that returns empty chunk
    mock_file_obj = Mock()
    mock_file_obj.info.meta.size = 1000
    mock_file_obj.read_random.return_value = b""  # Empty chunk

    mock_filesystem = Mock()
    mock_filesystem.open_meta.return_value = mock_file_obj
    mock_fs.return_value = mock_filesystem

    reader = ImageContentReader(image_path)
    entry = create_test_mft_entry()

    result = reader.read_file(entry)

    assert result == b""


@patch("sift_find_evil.parsers.image_content_reader.EwfImgInfo")
@patch("sift_find_evil.parsers.image_content_reader.pytsk3.FS_Info")
@patch("sift_find_evil.parsers.image_content_reader.pytsk3.Volume_Info")
@patch("sift_find_evil.parsers.image_content_reader.pyewf.handle")
@patch("sift_find_evil.parsers.image_content_reader.pyewf.glob")
def test_image_content_reader_read_file_raises_on_read_error(
    mock_glob, mock_handle_class, mock_volume, mock_fs, mock_ewf_img_info, tmp_path
):
    """Test ImageContentReader.read_file() raises RuntimeError on read error."""
    image_path = tmp_path / "test.E01"
    image_path.touch()

    mock_glob.return_value = [str(image_path)]
    mock_handle = Mock()
    mock_handle_class.return_value = mock_handle
    mock_volume.side_effect = Exception("No partition")

    # Mock file that raises exception on read
    mock_file_obj = Mock()
    mock_file_obj.info.meta.size = 1000
    mock_file_obj.read_random.side_effect = Exception("Read error")

    mock_filesystem = Mock()
    mock_filesystem.open_meta.return_value = mock_file_obj
    mock_fs.return_value = mock_filesystem

    reader = ImageContentReader(image_path)
    entry = create_test_mft_entry(entry_number=100)

    with pytest.raises(RuntimeError, match="Failed to read from MFT entry 100"):
        reader.read_file(entry)


# Tests for make_content_reader()


@patch("sift_find_evil.parsers.image_content_reader.ImageContentReader")
def test_make_content_reader_creates_closure(mock_reader_class):
    """Test make_content_reader() creates a closure that initializes reader on first use."""
    image_path = Path("/tmp/test.E01")

    mock_reader = Mock()
    mock_reader.read_file.return_value = b"test content"
    mock_reader_class.return_value = mock_reader

    reader_func = make_content_reader(image_path)

    # Reader should not be initialized yet
    mock_reader_class.assert_not_called()

    # First call initializes reader
    entry = create_test_mft_entry()
    result = reader_func(entry)

    assert result == b"test content"
    mock_reader_class.assert_called_once_with(image_path)
    mock_reader.read_file.assert_called_once_with(entry)


@patch("sift_find_evil.parsers.image_content_reader.ImageContentReader")
def test_make_content_reader_reuses_same_reader(mock_reader_class):
    """Test make_content_reader() reuses the same reader instance for multiple calls."""
    image_path = Path("/tmp/test.E01")

    mock_reader = Mock()
    mock_reader.read_file.return_value = b"test content"
    mock_reader_class.return_value = mock_reader

    reader_func = make_content_reader(image_path)

    entry1 = create_test_mft_entry(entry_number=1)
    entry2 = create_test_mft_entry(entry_number=2)

    reader_func(entry1)
    reader_func(entry2)

    # Reader should only be initialized once
    mock_reader_class.assert_called_once_with(image_path)

    # But read_file should be called twice
    assert mock_reader.read_file.call_count == 2
