"""MFT Parser - Parse MFTECmd CSV output.

Extracts file metadata and timestamps from Master File Table analysis.
"""

import csv
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, List, Optional
from pathlib import Path

from ..validators.timestamp_comparator import TimestampComparator

logger = logging.getLogger(__name__)


@dataclass
class MFTEntry:
    """Represents a single MFT entry with timestamps."""
    entry_number: int
    file_name: str
    parent_path: str
    file_path: str  # Full path (parent + file)
    file_size: int
    is_directory: bool
    in_use: bool

    # $STANDARD_INFORMATION timestamps (0x10 attribute)
    si_created: Optional[datetime]
    si_modified: Optional[datetime]
    si_accessed: Optional[datetime]
    si_mft_modified: Optional[datetime]

    # $FILE_NAME timestamps (0x30 attribute)
    fn_created: Optional[datetime]
    fn_modified: Optional[datetime]
    fn_accessed: Optional[datetime]
    fn_mft_modified: Optional[datetime]

    # Optional content reader for hash-based correlation (SFE-2)
    content_reader: Optional[Callable[["MFTEntry"], bytes]] = field(default=None, repr=False)

    def __post_init__(self):
        """Construct full file path after initialization."""
        if self.parent_path and self.file_name:
            # Ensure proper path separator
            parent = self.parent_path.rstrip('\\')
            self.file_path = f"{parent}\\{self.file_name}"

    def has_timestomping(self, comparator: TimestampComparator) -> Optional[dict]:
        """Check if this entry shows signs of timestomping.

        Returns:
            Dict with timestomping details, or None if no tampering detected
        """
        if self.si_modified and self.fn_modified:
            return comparator.detect_timestomping(self.si_modified, self.fn_modified)
        return None

    def get_creation_time(self, prefer_fn: bool = True) -> Optional[datetime]:
        """Get creation time, preferring $FILE_NAME over $STANDARD_INFORMATION.

        Args:
            prefer_fn: If True, prefer $FN over $SI (more reliable)

        Returns:
            Creation datetime, or None if not available
        """
        if prefer_fn:
            return self.fn_created or self.si_created
        return self.si_created or self.fn_created

    def get_modification_time(self, prefer_fn: bool = True) -> Optional[datetime]:
        """Get modification time, preferring $FILE_NAME over $STANDARD_INFORMATION.

        Args:
            prefer_fn: If True, prefer $FN over $SI (more reliable)

        Returns:
            Modification datetime, or None if not available
        """
        if prefer_fn:
            return self.fn_modified or self.si_modified
        return self.si_modified or self.fn_modified


class MFTParser:
    """Parser for MFTECmd CSV output.

    Reads MFT entries and extracts file metadata with timestamps.
    """

    def __init__(self):
        """Initialize the parser with a timestamp comparator."""
        self.comparator = TimestampComparator()

    def parse_csv(
        self,
        csv_path: str,
        content_reader: Optional[Callable[[MFTEntry], bytes]] = None,
    ) -> List[MFTEntry]:
        """Parse MFTECmd CSV file.

        Args:
            csv_path: Path to mft_parsed.csv
            content_reader: Optional callable that reads file bytes given an MFTEntry.
                           When None, entries have no content-reading capability (CSV-only mode).
                           When provided, each entry's content_reader field is populated.

        Returns:
            List of MFTEntry objects

        Raises:
            FileNotFoundError: If CSV file doesn't exist
            ValueError: If CSV format is invalid
        """
        csv_file = Path(csv_path)
        if not csv_file.exists():
            raise FileNotFoundError(f"MFT CSV not found: {csv_path}")

        entries = []

        with open(csv_file, 'r', encoding='utf-8-sig') as f:
            reader = csv.DictReader(f)

            for row in reader:
                entry = self._parse_row(row, content_reader=content_reader)
                if entry:
                    entries.append(entry)

        return entries

    def _parse_row(
        self, row: dict, content_reader: Optional[Callable[[MFTEntry], bytes]] = None
    ) -> Optional[MFTEntry]:
        """Parse a single CSV row into an MFTEntry.

        Args:
            row: Dictionary of CSV column values
            content_reader: Optional content reader to attach to the entry

        Returns:
            MFTEntry object, or None if row is invalid
        """
        try:
            # Parse entry number
            entry_number = int(row.get('EntryNumber', 0))

            # Parse file metadata
            file_name = row.get('FileName', '')
            parent_path = row.get('ParentPath', '')
            file_size = int(row.get('FileSize', 0))
            is_directory = row.get('IsDirectory', 'False').lower() == 'true'
            in_use = row.get('InUse', 'False').lower() == 'true'

            # Parse $STANDARD_INFORMATION timestamps
            # MFTECmd uses different column names depending on version
            si_created = self._parse_timestamp(
                row.get('Created0x10') or row.get('SI_LtCreated')
            )
            si_modified = self._parse_timestamp(
                row.get('LastModified0x10') or row.get('Modified0x10') or row.get('SI_LtModified')
            )
            si_accessed = self._parse_timestamp(
                row.get('LastAccess0x10') or row.get('Accessed0x10') or row.get('SI_LtAccess')
            )
            si_mft_modified = self._parse_timestamp(
                row.get('LastRecordChange0x10') or row.get('Changed0x10') or row.get('SI_LtMftModified')
            )

            # Parse $FILE_NAME timestamps
            fn_created = self._parse_timestamp(
                row.get('Created0x30') or row.get('FN_LtCreated')
            )
            fn_modified = self._parse_timestamp(
                row.get('LastModified0x30') or row.get('Modified0x30') or row.get('FN_LtModified')
            )
            fn_accessed = self._parse_timestamp(
                row.get('LastAccess0x30') or row.get('Accessed0x30') or row.get('FN_LtAccess')
            )
            fn_mft_modified = self._parse_timestamp(
                row.get('LastRecordChange0x30') or row.get('Changed0x30') or row.get('FN_LtMftModified')
            )

            return MFTEntry(
                entry_number=entry_number,
                file_name=file_name,
                parent_path=parent_path,
                file_path='',  # Will be constructed in __post_init__
                file_size=file_size,
                is_directory=is_directory,
                in_use=in_use,
                si_created=si_created,
                si_modified=si_modified,
                si_accessed=si_accessed,
                si_mft_modified=si_mft_modified,
                fn_created=fn_created,
                fn_modified=fn_modified,
                fn_accessed=fn_accessed,
                fn_mft_modified=fn_mft_modified,
                content_reader=content_reader,
            )

        except Exception as e:
            # Log error and skip invalid row
            logger.warning(f"Failed to parse MFT row: {e}")
            return None

    def _parse_timestamp(self, timestamp_str: Optional[str]) -> Optional[datetime]:
        """Parse timestamp string to datetime.

        Args:
            timestamp_str: ISO 8601 timestamp string

        Returns:
            Datetime object, or None if null/invalid
        """
        if not timestamp_str or timestamp_str.strip() == '':
            return None

        try:
            dt = self.comparator.parse_iso8601(timestamp_str)

            # Check if null timestamp
            if self.comparator.is_null(dt):
                return None

            # Ensure timezone-aware UTC (pypff returns aware, MFT must match)
            if dt.tzinfo is None:
                import pytz
                dt = dt.replace(tzinfo=pytz.utc)

            return dt
        except Exception:
            return None

    def find_by_filename(self, entries: List[MFTEntry], filename: str,
                        case_sensitive: bool = False) -> List[MFTEntry]:
        """Find MFT entries by filename.

        Args:
            entries: List of MFT entries to search
            filename: Filename to search for (e.g., "malware.exe")
            case_sensitive: Whether search should be case-sensitive

        Returns:
            List of matching MFT entries
        """
        if case_sensitive:
            return [e for e in entries if e.file_name == filename]
        else:
            filename_lower = filename.lower()
            return [e for e in entries if e.file_name.lower() == filename_lower]

    def find_by_path(self, entries: List[MFTEntry], path_pattern: str,
                    case_sensitive: bool = False) -> List[MFTEntry]:
        r"""Find MFT entries by path pattern.

        Args:
            entries: List of MFT entries to search
            path_pattern: Path pattern to search (e.g., r"C:\Temp\")
            case_sensitive: Whether search should be case-sensitive

        Returns:
            List of matching MFT entries
        """
        if case_sensitive:
            return [e for e in entries if path_pattern in e.file_path]
        else:
            pattern_lower = path_pattern.lower()
            return [e for e in entries if pattern_lower in e.file_path.lower()]

    def find_timestomped_files(self, entries: List[MFTEntry]) -> List[tuple]:
        """Find all files with timestomping indicators.

        Args:
            entries: List of MFT entries to check

        Returns:
            List of tuples: (MFTEntry, timestomping_details)
        """
        timestomped = []

        for entry in entries:
            details = entry.has_timestomping(self.comparator)
            if details:
                timestomped.append((entry, details))

        return timestomped

    def get_recently_modified(self, entries: List[MFTEntry],
                             within_hours: int = 24) -> List[MFTEntry]:
        """Get files modified within a time window.

        Args:
            entries: List of MFT entries
            within_hours: Time window in hours

        Returns:
            List of recently modified entries
        """
        from datetime import timedelta
        import pytz

        now = datetime.now(pytz.utc)
        cutoff = now - timedelta(hours=within_hours)

        recent = []
        for entry in entries:
            mod_time = entry.get_modification_time(prefer_fn=True)
            if mod_time and mod_time > cutoff:
                recent.append(entry)

        return recent
