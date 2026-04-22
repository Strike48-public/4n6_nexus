"""Tests for browser history parser."""

import csv
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

import pytest

from sift_find_evil.parsers.browser_history_parser import (
    BrowserHistoryEntry,
    BrowserHistoryParser,
)


@pytest.fixture
def temp_chrome_db(tmp_path):
    """Create temporary Chrome History SQLite database."""
    db_path = tmp_path / "History"

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Create Chrome schema
    cursor.execute(
        """
        CREATE TABLE urls (
            id INTEGER PRIMARY KEY,
            url TEXT NOT NULL,
            title TEXT,
            visit_count INTEGER DEFAULT 0
        )
    """
    )

    cursor.execute(
        """
        CREATE TABLE visits (
            id INTEGER PRIMARY KEY,
            url INTEGER NOT NULL,
            visit_time INTEGER NOT NULL,
            from_visit INTEGER,
            FOREIGN KEY (url) REFERENCES urls(id)
        )
    """
    )

    # Insert test data
    # Chrome WebKit timestamp: microseconds since 1601-01-01
    # For 2025-03-15T10:30:00Z:
    # Unix timestamp: 1742034600
    # WebKit timestamp: (1742034600 + 11644473600) * 1000000 = 13386508200000000
    webkit_time = 13386508200000000  # 2025-03-15T10:30:00Z

    cursor.execute(
        "INSERT INTO urls (id, url, title, visit_count) VALUES (?, ?, ?, ?)",
        (1, "https://gmail.com", "Gmail", 5),
    )
    cursor.execute(
        "INSERT INTO urls (id, url, title, visit_count) VALUES (?, ?, ?, ?)",
        (2, "https://drive.google.com", "Google Drive", 2),
    )
    cursor.execute(
        "INSERT INTO urls (id, url, title, visit_count) VALUES (?, ?, ?, ?)",
        (3, "https://dropbox.com/upload", None, 1),
    )

    cursor.execute(
        "INSERT INTO visits (id, url, visit_time, from_visit) VALUES (?, ?, ?, ?)",
        (1, 1, webkit_time, None),
    )
    cursor.execute(
        "INSERT INTO visits (id, url, visit_time, from_visit) VALUES (?, ?, ?, ?)",
        (2, 2, webkit_time + 1_000_000, None),
    )  # +1 second
    cursor.execute(
        "INSERT INTO visits (id, url, visit_time, from_visit) VALUES (?, ?, ?, ?)",
        (3, 3, webkit_time + 2_000_000, None),
    )  # +2 seconds

    conn.commit()
    conn.close()

    return db_path


@pytest.fixture
def temp_firefox_db(tmp_path):
    """Create temporary Firefox places.sqlite database."""
    db_path = tmp_path / "places.sqlite"

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Create Firefox schema
    cursor.execute(
        """
        CREATE TABLE moz_places (
            id INTEGER PRIMARY KEY,
            url TEXT NOT NULL,
            title TEXT,
            visit_count INTEGER DEFAULT 0
        )
    """
    )

    cursor.execute(
        """
        CREATE TABLE moz_historyvisits (
            id INTEGER PRIMARY KEY,
            place_id INTEGER NOT NULL,
            visit_date INTEGER NOT NULL,
            FOREIGN KEY (place_id) REFERENCES moz_places(id)
        )
    """
    )

    # Insert test data
    # Firefox timestamp: microseconds since Unix epoch (1970-01-01)
    # For 2025-03-15T10:30:00Z: 1742034600 * 1000000 = 1742034600000000
    firefox_time = 1742034600000000

    cursor.execute(
        "INSERT INTO moz_places (id, url, title, visit_count) VALUES (?, ?, ?, ?)",
        (1, "https://mail.yahoo.com", "Yahoo Mail", 3),
    )
    cursor.execute(
        "INSERT INTO moz_places (id, url, title, visit_count) VALUES (?, ?, ?, ?)",
        (2, "https://onedrive.live.com", "OneDrive", 1),
    )

    cursor.execute(
        "INSERT INTO moz_historyvisits (id, place_id, visit_date) VALUES (?, ?, ?)",
        (1, 1, firefox_time),
    )
    cursor.execute(
        "INSERT INTO moz_historyvisits (id, place_id, visit_date) VALUES (?, ?, ?)",
        (2, 2, firefox_time + 1_000_000),
    )  # +1 second

    conn.commit()
    conn.close()

    return db_path


@pytest.fixture
def temp_csv(tmp_path):
    """Create temporary browser history CSV file."""
    csv_path = tmp_path / "browser_history.csv"

    with csv_path.open("w", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "timestamp",
                "url",
                "title",
                "visit_count",
                "browser",
                "profile",
            ],
        )
        writer.writeheader()
        writer.writerow(
            {
                "timestamp": "2025-03-15T10:30:00Z",
                "url": "https://gmail.com",
                "title": "Gmail",
                "visit_count": "5",
                "browser": "chrome",
                "profile": "Default",
            }
        )
        writer.writerow(
            {
                "timestamp": "2025-03-15T10:30:05Z",
                "url": "https://dropbox.com/upload",
                "title": "",
                "visit_count": "1",
                "browser": "chrome",
                "profile": "Default",
            }
        )

    return csv_path


# Test BrowserHistoryEntry dataclass
def test_browser_history_entry_valid():
    """Test valid browser history entry creation."""
    entry = BrowserHistoryEntry(
        timestamp=datetime(2025, 3, 15, 10, 30, 0, tzinfo=timezone.utc),
        url="https://gmail.com",
        title="Gmail",
        visit_count=5,
        browser="chrome",
        profile="Default",
    )

    assert entry.timestamp == datetime(2025, 3, 15, 10, 30, 0, tzinfo=timezone.utc)
    assert entry.url == "https://gmail.com"
    assert entry.title == "Gmail"
    assert entry.visit_count == 5
    assert entry.browser == "chrome"
    assert entry.profile == "Default"


def test_browser_history_entry_invalid_browser():
    """Test browser history entry with invalid browser."""
    with pytest.raises(ValueError, match="Invalid browser"):
        BrowserHistoryEntry(
            timestamp=datetime(2025, 3, 15, 10, 30, 0, tzinfo=timezone.utc),
            url="https://gmail.com",
            title="Gmail",
            visit_count=5,
            browser="safari",  # Not supported yet
            profile="Default",
        )


def test_browser_history_entry_empty_url():
    """Test browser history entry with empty URL."""
    with pytest.raises(ValueError, match="URL cannot be empty"):
        BrowserHistoryEntry(
            timestamp=datetime(2025, 3, 15, 10, 30, 0, tzinfo=timezone.utc),
            url="",
            title="Gmail",
            visit_count=5,
            browser="chrome",
            profile="Default",
        )


def test_browser_history_entry_none_title():
    """Test browser history entry with None title."""
    entry = BrowserHistoryEntry(
        timestamp=datetime(2025, 3, 15, 10, 30, 0, tzinfo=timezone.utc),
        url="https://gmail.com",
        title=None,
        visit_count=5,
        browser="chrome",
        profile="Default",
    )

    assert entry.title is None


# Test Chrome parser
def test_parse_chrome_success(temp_chrome_db):
    """Test parsing Chrome history database."""
    parser = BrowserHistoryParser()
    entries = parser.parse_chrome(temp_chrome_db, profile="Default")

    assert len(entries) == 3

    # First entry: Gmail
    assert entries[0].url == "https://gmail.com"
    assert entries[0].title == "Gmail"
    assert entries[0].visit_count == 5
    assert entries[0].browser == "chrome"
    assert entries[0].profile == "Default"
    # Verify timestamp conversion (2025-03-15T10:30:00Z)
    assert entries[0].timestamp.year == 2025
    assert entries[0].timestamp.month == 3
    assert entries[0].timestamp.day == 15

    # Second entry: Google Drive
    assert entries[1].url == "https://drive.google.com"
    assert entries[1].title == "Google Drive"

    # Third entry: Dropbox (no title)
    assert entries[2].url == "https://dropbox.com/upload"
    assert entries[2].title is None


def test_parse_chrome_file_not_found():
    """Test Chrome parser with non-existent file."""
    parser = BrowserHistoryParser()

    with pytest.raises(FileNotFoundError, match="Chrome History database not found"):
        parser.parse_chrome(Path("/nonexistent/History"))


def test_parse_chrome_corrupted_db(tmp_path):
    """Test Chrome parser with corrupted database."""
    db_path = tmp_path / "History"
    db_path.write_text("NOT A VALID SQLITE DATABASE")

    parser = BrowserHistoryParser()

    with pytest.raises(sqlite3.DatabaseError):
        parser.parse_chrome(db_path)


# Test Firefox parser
def test_parse_firefox_success(temp_firefox_db):
    """Test parsing Firefox places.sqlite database."""
    parser = BrowserHistoryParser()
    entries = parser.parse_firefox(temp_firefox_db, profile="default")

    assert len(entries) == 2

    # First entry: Yahoo Mail
    assert entries[0].url == "https://mail.yahoo.com"
    assert entries[0].title == "Yahoo Mail"
    assert entries[0].visit_count == 3
    assert entries[0].browser == "firefox"
    assert entries[0].profile == "default"
    # Verify timestamp conversion
    assert entries[0].timestamp.year == 2025
    assert entries[0].timestamp.month == 3
    assert entries[0].timestamp.day == 15

    # Second entry: OneDrive
    assert entries[1].url == "https://onedrive.live.com"
    assert entries[1].title == "OneDrive"


def test_parse_firefox_file_not_found():
    """Test Firefox parser with non-existent file."""
    parser = BrowserHistoryParser()

    with pytest.raises(FileNotFoundError, match="Firefox places.sqlite not found"):
        parser.parse_firefox(Path("/nonexistent/places.sqlite"))


# Test CSV parser
def test_parse_csv_success(temp_csv):
    """Test parsing browser history from CSV."""
    parser = BrowserHistoryParser()
    entries = parser.parse_csv(temp_csv)

    assert len(entries) == 2

    # First entry
    assert entries[0].url == "https://gmail.com"
    assert entries[0].title == "Gmail"
    assert entries[0].visit_count == 5
    assert entries[0].browser == "chrome"
    assert entries[0].timestamp == datetime(2025, 3, 15, 10, 30, 0, tzinfo=timezone.utc)

    # Second entry (empty title)
    assert entries[1].url == "https://dropbox.com/upload"
    assert entries[1].title is None
    assert entries[1].visit_count == 1


def test_parse_csv_file_not_found():
    """Test CSV parser with non-existent file."""
    parser = BrowserHistoryParser()

    with pytest.raises(FileNotFoundError, match="Browser history CSV not found"):
        parser.parse_csv(Path("/nonexistent/browser_history.csv"))


def test_parse_csv_invalid_format(tmp_path):
    """Test CSV parser with invalid format."""
    csv_path = tmp_path / "invalid.csv"
    csv_path.write_text(
        "timestamp,url\n2025-03-15,https://example.com\n"
    )  # Missing required fields

    parser = BrowserHistoryParser()

    with pytest.raises(ValueError, match="Invalid browser history CSV format"):
        parser.parse_csv(csv_path)


def test_parse_csv_invalid_timestamp(tmp_path):
    """Test CSV parser with invalid timestamp."""
    csv_path = tmp_path / "invalid_timestamp.csv"

    with csv_path.open("w", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "timestamp",
                "url",
                "title",
                "visit_count",
                "browser",
                "profile",
            ],
        )
        writer.writeheader()
        writer.writerow(
            {
                "timestamp": "INVALID",
                "url": "https://gmail.com",
                "title": "Gmail",
                "visit_count": "5",
                "browser": "chrome",
                "profile": "Default",
            }
        )

    parser = BrowserHistoryParser()

    with pytest.raises(ValueError):
        parser.parse_csv(csv_path)


# Test CSV export
def test_export_csv(temp_chrome_db, tmp_path):
    """Test exporting browser history to CSV."""
    parser = BrowserHistoryParser()
    entries = parser.parse_chrome(temp_chrome_db)

    output_path = tmp_path / "output.csv"
    parser.export_csv(entries, output_path)

    # Verify exported file
    assert output_path.exists()

    # Re-parse exported CSV
    exported_entries = parser.parse_csv(output_path)
    assert len(exported_entries) == len(entries)

    # Verify first entry
    assert exported_entries[0].url == entries[0].url
    assert exported_entries[0].title == entries[0].title
    assert exported_entries[0].visit_count == entries[0].visit_count


# Edge cases
def test_parse_chrome_empty_database(tmp_path):
    """Test Chrome parser with empty database."""
    db_path = tmp_path / "History"

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Create schema but no data
    cursor.execute(
        "CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER)"
    )
    cursor.execute(
        "CREATE TABLE visits (id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER)"
    )

    conn.commit()
    conn.close()

    parser = BrowserHistoryParser()
    entries = parser.parse_chrome(db_path)

    assert len(entries) == 0


def test_webkit_timestamp_conversion():
    """Test Chrome WebKit timestamp conversion accuracy."""
    parser = BrowserHistoryParser()

    # Known WebKit timestamp for 2025-03-15T10:30:00Z
    webkit_time = 13386508200000000
    expected_unix = 1742034600

    # Convert using parser's method
    unix_timestamp = (webkit_time / 1_000_000) - parser.WEBKIT_EPOCH_OFFSET

    assert abs(unix_timestamp - expected_unix) < 1  # Within 1 second tolerance


def test_firefox_timestamp_conversion(temp_firefox_db):
    """Test Firefox timestamp conversion accuracy."""
    parser = BrowserHistoryParser()
    entries = parser.parse_firefox(temp_firefox_db)

    # Verify timestamp is 2025-03-15T10:30:00Z
    expected = datetime(2025, 3, 15, 10, 30, 0, tzinfo=timezone.utc)
    assert entries[0].timestamp == expected
