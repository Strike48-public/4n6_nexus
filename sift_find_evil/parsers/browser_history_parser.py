"""Browser History Parser - Parse browser history from SQLite databases.

Extracts URL visits, page titles, and timestamps from Chrome, Firefox, and Edge
browser history databases for web-based C2 and cloud exfiltration detection.
"""

import csv
import logging
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class BrowserHistoryEntry:
    """Represents a single browser history entry.

    Attributes:
        timestamp: When the URL was visited
        url: Full URL visited
        title: Page title (may be None)
        visit_count: Number of times visited
        browser: Browser name ("chrome", "firefox", "edge")
        profile: Browser profile name (e.g., "Default", "Profile 1")
    """

    timestamp: datetime
    url: str
    title: Optional[str]
    visit_count: int
    browser: str  # "chrome", "firefox", "edge"
    profile: str  # "Default", "Profile 1", etc.

    def __post_init__(self):
        """Validate browser history entry."""
        if self.browser not in ("chrome", "firefox", "edge"):
            raise ValueError(f"Invalid browser: {self.browser}")
        if not self.url:
            raise ValueError("URL cannot be empty")


class BrowserHistoryParser:
    """Parse browser history from SQLite databases.

    Supports:
    - Chrome: History SQLite database
    - Firefox: places.sqlite database
    - Edge: WebCacheV01.dat (ESE database, requires external tools)

    Chrome WebKit timestamp format:
        - Microseconds since January 1, 1601 (Windows epoch)
        - Convert: (webkit_timestamp / 1000000) - 11644473600 = Unix timestamp

    Firefox timestamp format:
        - Microseconds since Unix epoch (1970-01-01)
        - Convert: firefox_timestamp / 1000000 = Unix timestamp
    """

    # Chrome WebKit epoch offset (seconds from 1601-01-01 to 1970-01-01)
    WEBKIT_EPOCH_OFFSET = 11644473600

    def parse_chrome(self, db_path: Path, profile: str = "Default") -> list[BrowserHistoryEntry]:
        """Parse Chrome History SQLite database.

        Args:
            db_path: Path to Chrome History database (usually ~/.config/google-chrome/Default/History)
            profile: Profile name (e.g., "Default", "Profile 1")

        Returns:
            List of browser history entries

        Raises:
            FileNotFoundError: If database file doesn't exist
            sqlite3.DatabaseError: If database is corrupted or locked

        Example:
            >>> parser = BrowserHistoryParser()
            >>> entries = parser.parse_chrome(Path("/home/user/.config/google-chrome/Default/History"))
            >>> print(f"Found {len(entries)} Chrome history entries")
        """
        if not db_path.exists():
            raise FileNotFoundError(f"Chrome History database not found: {db_path}")

        entries = []

        try:
            # Chrome databases are often locked - use read-only mode
            conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
            cursor = conn.cursor()

            # Query Chrome history
            # Schema: urls(id, url, title, visit_count, last_visit_time)
            #         visits(id, url, visit_time, from_visit)
            query = """
                SELECT
                    visits.visit_time,
                    urls.url,
                    urls.title,
                    urls.visit_count
                FROM visits
                JOIN urls ON visits.url = urls.id
                ORDER BY visits.visit_time ASC
            """

            cursor.execute(query)

            for row in cursor.fetchall():
                webkit_time, url, title, visit_count = row

                # Convert Chrome WebKit timestamp to Unix timestamp
                # WebKit: microseconds since 1601-01-01
                # Unix: seconds since 1970-01-01
                unix_timestamp = (webkit_time / 1_000_000) - self.WEBKIT_EPOCH_OFFSET
                timestamp = datetime.fromtimestamp(unix_timestamp, tz=timezone.utc)

                entries.append(BrowserHistoryEntry(
                    timestamp=timestamp,
                    url=url,
                    title=title,
                    visit_count=visit_count,
                    browser="chrome",
                    profile=profile
                ))

            conn.close()
            logger.info(f"Parsed {len(entries)} Chrome history entries from {db_path}")

        except sqlite3.DatabaseError as e:
            logger.error(f"Failed to parse Chrome history from {db_path}: {e}")
            raise

        return entries

    def parse_firefox(self, db_path: Path, profile: str = "default") -> list[BrowserHistoryEntry]:
        """Parse Firefox places.sqlite database.

        Args:
            db_path: Path to Firefox places.sqlite (usually ~/.mozilla/firefox/*.default/places.sqlite)
            profile: Profile name (e.g., "default", "profile1")

        Returns:
            List of browser history entries

        Raises:
            FileNotFoundError: If database file doesn't exist
            sqlite3.DatabaseError: If database is corrupted or locked

        Example:
            >>> parser = BrowserHistoryParser()
            >>> entries = parser.parse_firefox(Path("/home/user/.mozilla/firefox/abc123.default/places.sqlite"))
            >>> print(f"Found {len(entries)} Firefox history entries")
        """
        if not db_path.exists():
            raise FileNotFoundError(f"Firefox places.sqlite not found: {db_path}")

        entries = []

        try:
            conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
            cursor = conn.cursor()

            # Query Firefox history
            # Schema: moz_places(id, url, title, visit_count)
            #         moz_historyvisits(id, place_id, visit_date)
            query = """
                SELECT
                    moz_historyvisits.visit_date,
                    moz_places.url,
                    moz_places.title,
                    moz_places.visit_count
                FROM moz_historyvisits
                JOIN moz_places ON moz_historyvisits.place_id = moz_places.id
                ORDER BY moz_historyvisits.visit_date ASC
            """

            cursor.execute(query)

            for row in cursor.fetchall():
                firefox_time, url, title, visit_count = row

                # Convert Firefox timestamp to Unix timestamp
                # Firefox: microseconds since Unix epoch (1970-01-01)
                unix_timestamp = firefox_time / 1_000_000
                timestamp = datetime.fromtimestamp(unix_timestamp, tz=timezone.utc)

                entries.append(BrowserHistoryEntry(
                    timestamp=timestamp,
                    url=url,
                    title=title,
                    visit_count=visit_count,
                    browser="firefox",
                    profile=profile
                ))

            conn.close()
            logger.info(f"Parsed {len(entries)} Firefox history entries from {db_path}")

        except sqlite3.DatabaseError as e:
            logger.error(f"Failed to parse Firefox history from {db_path}: {e}")
            raise

        return entries

    def parse_csv(self, csv_path: Path) -> list[BrowserHistoryEntry]:
        """Parse browser history from CSV export.

        CSV format:
            timestamp,url,title,visit_count,browser,profile
            2025-03-15T10:30:00Z,https://gmail.com,Gmail,5,chrome,Default

        Args:
            csv_path: Path to CSV file

        Returns:
            List of browser history entries

        Raises:
            FileNotFoundError: If CSV file doesn't exist
            ValueError: If CSV format is invalid

        Example:
            >>> parser = BrowserHistoryParser()
            >>> entries = parser.parse_csv(Path("browser_history.csv"))
        """
        if not csv_path.exists():
            raise FileNotFoundError(f"Browser history CSV not found: {csv_path}")

        entries = []

        try:
            with csv_path.open("r", encoding="utf-8") as f:
                reader = csv.DictReader(f)

                for row in reader:
                    # Parse timestamp (ISO 8601 format)
                    timestamp = datetime.fromisoformat(row["timestamp"].replace("Z", "+00:00"))

                    # Parse visit count (may be empty string)
                    visit_count = int(row.get("visit_count", "1") or "1")

                    entries.append(BrowserHistoryEntry(
                        timestamp=timestamp,
                        url=row["url"],
                        title=row.get("title") or None,
                        visit_count=visit_count,
                        browser=row["browser"],
                        profile=row.get("profile", "Default")
                    ))

            logger.info(f"Parsed {len(entries)} browser history entries from CSV {csv_path}")

        except (KeyError, ValueError) as e:
            logger.error(f"Invalid CSV format in {csv_path}: {e}")
            raise ValueError(f"Invalid browser history CSV format: {e}")

        return entries

    def export_csv(self, entries: list[BrowserHistoryEntry], output_path: Path) -> None:
        """Export browser history entries to CSV.

        Args:
            entries: List of browser history entries
            output_path: Path to output CSV file

        Example:
            >>> parser = BrowserHistoryParser()
            >>> entries = parser.parse_chrome(Path("History"))
            >>> parser.export_csv(entries, Path("browser_history.csv"))
        """
        with output_path.open("w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(
                f,
                fieldnames=["timestamp", "url", "title", "visit_count", "browser", "profile"]
            )
            writer.writeheader()

            for entry in entries:
                writer.writerow({
                    "timestamp": entry.timestamp.isoformat(),
                    "url": entry.url,
                    "title": entry.title or "",
                    "visit_count": entry.visit_count,
                    "browser": entry.browser,
                    "profile": entry.profile
                })

        logger.info(f"Exported {len(entries)} browser history entries to {output_path}")
