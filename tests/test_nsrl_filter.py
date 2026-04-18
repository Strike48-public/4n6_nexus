"""Tests for NSRL (National Software Reference Library) hash filtering."""

import pytest
import tempfile
from pathlib import Path
from sift_find_evil.carving.nsrl_filter import NSRLFilter, find_nsrl_database


@pytest.fixture
def mock_nsrl_file():
    """Create a mock NSRLFile.txt for testing."""
    content = '''"SHA-1","MD5","CRC32","FileName","FileSize","ProductCode","OpSystemCode","SpecialCode"
"5d41402abc4b2a76b9719d911017c592","7d793037a0760186574b0282f2f435e7","12345678","kernel32.dll","1024","1001","WindowsXP",""
"aaf4c61ddcc5e8a2dabede0f3b482cd9","098f6bcd4621d373cade4e832627b4f6","87654321","explorer.exe","2048","1002","WindowsXP",""
"9c2e4d0d9a1c66c5d6e4e35c6b7d1234","5f4dcc3b5aa765d61d8327deb882cf99","11223344","notepad.exe","512","1003","WindowsXP",""
'''

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write(content)
        f.flush()
        yield Path(f.name)

    # Cleanup
    Path(f.name).unlink(missing_ok=True)


def test_nsrl_filter_init_valid_path(mock_nsrl_file):
    """Test NSRLFilter initialization with valid path."""
    nsrl_filter = NSRLFilter(mock_nsrl_file)
    assert nsrl_filter.nsrl_path == mock_nsrl_file
    assert not nsrl_filter.loaded


def test_nsrl_filter_init_invalid_path():
    """Test NSRLFilter initialization with invalid path raises FileNotFoundError."""
    with pytest.raises(FileNotFoundError, match="NSRL database not found"):
        NSRLFilter("/nonexistent/path/NSRLFile.txt")


def test_nsrl_filter_load(mock_nsrl_file):
    """Test loading NSRL database into memory."""
    nsrl_filter = NSRLFilter(mock_nsrl_file)
    nsrl_filter.load()

    assert nsrl_filter.loaded
    assert len(nsrl_filter.sha1_hashes) == 3
    assert len(nsrl_filter.md5_hashes) == 3


def test_nsrl_filter_load_idempotent(mock_nsrl_file):
    """Test loading NSRL database multiple times is idempotent."""
    nsrl_filter = NSRLFilter(mock_nsrl_file)
    nsrl_filter.load()
    initial_sha1_count = len(nsrl_filter.sha1_hashes)

    nsrl_filter.load()  # Load again
    assert len(nsrl_filter.sha1_hashes) == initial_sha1_count


def test_is_known_good_sha1_match(mock_nsrl_file):
    """Test is_known_good returns True for SHA-1 hash in database."""
    nsrl_filter = NSRLFilter(mock_nsrl_file)
    nsrl_filter.load()

    # kernel32.dll SHA-1
    assert nsrl_filter.is_known_good("5d41402abc4b2a76b9719d911017c592", hash_type="sha1")


def test_is_known_good_sha1_no_match(mock_nsrl_file):
    """Test is_known_good returns False for SHA-1 hash not in database."""
    nsrl_filter = NSRLFilter(mock_nsrl_file)
    nsrl_filter.load()

    assert not nsrl_filter.is_known_good("ffffffffffffffffffffffffffffffffffffffff", hash_type="sha1")


def test_is_known_good_md5_match(mock_nsrl_file):
    """Test is_known_good returns True for MD5 hash in database."""
    nsrl_filter = NSRLFilter(mock_nsrl_file)
    nsrl_filter.load()

    # kernel32.dll MD5
    assert nsrl_filter.is_known_good("7d793037a0760186574b0282f2f435e7", hash_type="md5")


def test_is_known_good_md5_no_match(mock_nsrl_file):
    """Test is_known_good returns False for MD5 hash not in database."""
    nsrl_filter = NSRLFilter(mock_nsrl_file)
    nsrl_filter.load()

    assert not nsrl_filter.is_known_good("ffffffffffffffffffffffffffffffff", hash_type="md5")


def test_is_known_good_case_insensitive(mock_nsrl_file):
    """Test is_known_good is case-insensitive."""
    nsrl_filter = NSRLFilter(mock_nsrl_file)
    nsrl_filter.load()

    # Test uppercase SHA-1
    assert nsrl_filter.is_known_good("5D41402ABC4B2A76B9719D911017C592", hash_type="sha1")

    # Test mixed case MD5
    assert nsrl_filter.is_known_good("7D793037a0760186574B0282f2f435E7", hash_type="md5")


def test_is_known_good_sha256_not_supported(mock_nsrl_file):
    """Test is_known_good returns False for SHA-256 (not supported by NSRL)."""
    nsrl_filter = NSRLFilter(mock_nsrl_file)
    nsrl_filter.load()

    sha256_hash = "a" * 64
    assert not nsrl_filter.is_known_good(sha256_hash, hash_type="sha256")


def test_is_known_good_invalid_hash_type(mock_nsrl_file):
    """Test is_known_good raises ValueError for invalid hash type."""
    nsrl_filter = NSRLFilter(mock_nsrl_file)
    nsrl_filter.load()

    with pytest.raises(ValueError, match="Unsupported hash type"):
        nsrl_filter.is_known_good("abc123", hash_type="invalid")


def test_is_known_good_auto_loads(mock_nsrl_file):
    """Test is_known_good automatically loads database if not loaded."""
    nsrl_filter = NSRLFilter(mock_nsrl_file)
    assert not nsrl_filter.loaded

    # Should auto-load
    result = nsrl_filter.is_known_good("5d41402abc4b2a76b9719d911017c592", hash_type="sha1")

    assert nsrl_filter.loaded
    assert result is True


def test_filter_files(mock_nsrl_file):
    """Test filter_files separates known-good from unknown."""
    nsrl_filter = NSRLFilter(mock_nsrl_file)

    files = [
        ("/carved/file1.dll", "5d41402abc4b2a76b9719d911017c592"),  # kernel32.dll (known-good)
        ("/carved/file2.exe", "aaf4c61ddcc5e8a2dabede0f3b482cd9"),  # explorer.exe (known-good)
        ("/carved/file3.exe", "0000000000000000000000000000000000000000"),  # unknown
        ("/carved/file4.exe", "1111111111111111111111111111111111111111"),  # unknown
    ]

    known_good, unknown = nsrl_filter.filter_files(files, hash_type="sha1")

    assert len(known_good) == 2
    assert len(unknown) == 2
    assert known_good[0][0] == "/carved/file1.dll"
    assert known_good[1][0] == "/carved/file2.exe"
    assert unknown[0][0] == "/carved/file3.exe"
    assert unknown[1][0] == "/carved/file4.exe"


def test_filter_files_empty_list(mock_nsrl_file):
    """Test filter_files handles empty file list."""
    nsrl_filter = NSRLFilter(mock_nsrl_file)

    known_good, unknown = nsrl_filter.filter_files([], hash_type="sha1")

    assert len(known_good) == 0
    assert len(unknown) == 0


def test_filter_files_all_known_good(mock_nsrl_file):
    """Test filter_files when all files are known-good."""
    nsrl_filter = NSRLFilter(mock_nsrl_file)

    files = [
        ("/carved/file1.dll", "5d41402abc4b2a76b9719d911017c592"),
        ("/carved/file2.exe", "aaf4c61ddcc5e8a2dabede0f3b482cd9"),
    ]

    known_good, unknown = nsrl_filter.filter_files(files, hash_type="sha1")

    assert len(known_good) == 2
    assert len(unknown) == 0


def test_filter_files_all_unknown(mock_nsrl_file):
    """Test filter_files when all files are unknown."""
    nsrl_filter = NSRLFilter(mock_nsrl_file)

    files = [
        ("/carved/malware1.exe", "0000000000000000000000000000000000000000"),
        ("/carved/malware2.exe", "1111111111111111111111111111111111111111"),
    ]

    known_good, unknown = nsrl_filter.filter_files(files, hash_type="sha1")

    assert len(known_good) == 0
    assert len(unknown) == 2


def test_get_stats_before_load(mock_nsrl_file):
    """Test get_stats before loading database."""
    nsrl_filter = NSRLFilter(mock_nsrl_file)

    stats = nsrl_filter.get_stats()

    assert stats["loaded"] is False
    assert stats["sha1_count"] == 0
    assert stats["md5_count"] == 0


def test_get_stats_after_load(mock_nsrl_file):
    """Test get_stats after loading database."""
    nsrl_filter = NSRLFilter(mock_nsrl_file)
    nsrl_filter.load()

    stats = nsrl_filter.get_stats()

    assert stats["loaded"] is True
    assert stats["sha1_count"] == 3
    assert stats["md5_count"] == 3


def test_find_nsrl_database_not_found(monkeypatch):
    """Test find_nsrl_database returns None when not found."""
    def mock_exists(self):
        return False

    monkeypatch.setattr(Path, "exists", mock_exists)

    result = find_nsrl_database()
    assert result is None


def test_find_nsrl_database_in_home(monkeypatch, tmp_path):
    """Test find_nsrl_database finds database in home directory."""
    home_nsrl = tmp_path / ".sift_find_evil" / "nsrl" / "NSRLFile.txt"
    home_nsrl.parent.mkdir(parents=True)
    home_nsrl.write_text("test")

    monkeypatch.setattr(Path, "home", lambda: tmp_path)

    result = find_nsrl_database()
    assert result == home_nsrl


def test_nsrl_filter_invalid_format():
    """Test NSRLFilter raises ValueError for invalid CSV format."""
    content = "InvalidHeader1,InvalidHeader2\ndata1,data2\n"

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write(content)
        f.flush()
        temp_path = Path(f.name)

    try:
        nsrl_filter = NSRLFilter(temp_path)
        with pytest.raises(ValueError, match="Invalid NSRL format"):
            nsrl_filter.load()
    finally:
        temp_path.unlink()
