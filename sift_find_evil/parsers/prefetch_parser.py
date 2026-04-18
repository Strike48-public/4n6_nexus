"""
Prefetch Parser - Parse PECmd CSV output.

Extracts program execution evidence from Windows Prefetch files.
"""

import csv
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional
from pathlib import Path

from ..validators.timestamp_comparator import TimestampComparator

logger = logging.getLogger(__name__)


@dataclass
class PrefetchEntry:
    """
    Represents a single Prefetch file with execution timestamps.
    """
    source_filename: str  # Prefetch file name (e.g., MALWARE.EXE-ABCD1234.pf)
    executable: str  # Executable name (e.g., MALWARE.EXE)
    run_count: int
    last_run_time: Optional[datetime]
    previous_run_times: List[datetime] = field(default_factory=list)  # Up to 7 additional runs
    files_loaded: List[str] = field(default_factory=list)  # DLLs and files loaded
    volume_name: Optional[str] = None
    volume_serial: Optional[str] = None
    hash_value: Optional[str] = None

    def get_all_run_times(self) -> List[datetime]:
        """
        Get all execution timestamps, sorted newest to oldest.

        Returns:
            List of execution datetimes
        """
        times = []
        if self.last_run_time:
            times.append(self.last_run_time)
        times.extend(self.previous_run_times)
        return times

    def get_first_run_time(self) -> Optional[datetime]:
        """
        Get earliest execution time.

        Returns:
            Oldest execution datetime, or None if no timestamps
        """
        all_times = self.get_all_run_times()
        return min(all_times) if all_times else None

    def was_executed_at(self, target_time: datetime,
                       tolerance_seconds: int = 5) -> bool:
        """
        Check if executable was run within tolerance window of target time.

        Args:
            target_time: Time to check against
            tolerance_seconds: Tolerance window (default 5 seconds)

        Returns:
            True if any execution time matches within tolerance
        """
        comparator = TimestampComparator(default_tolerance_seconds=tolerance_seconds)

        for run_time in self.get_all_run_times():
            comparison = comparator.compare(run_time, target_time, tolerance_seconds)
            if comparison == 0:  # Within tolerance
                return True

        return False


class PrefetchParser:
    """
    Parser for PECmd CSV output.

    Reads Prefetch entries and extracts execution evidence.
    """

    def __init__(self):
        self.comparator = TimestampComparator()

    def parse_csv(self, csv_path: str) -> List[PrefetchEntry]:
        """
        Parse PECmd CSV file.

        Args:
            csv_path: Path to prefetch_parsed.csv

        Returns:
            List of PrefetchEntry objects

        Raises:
            FileNotFoundError: If CSV file doesn't exist
            ValueError: If CSV format is invalid
        """
        csv_file = Path(csv_path)
        if not csv_file.exists():
            raise FileNotFoundError(f"Prefetch CSV not found: {csv_path}")

        entries = []

        with open(csv_file, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)

            for row in reader:
                entry = self._parse_row(row)
                if entry:
                    entries.append(entry)

        return entries

    def _parse_row(self, row: dict) -> Optional[PrefetchEntry]:
        """
        Parse a single CSV row into a PrefetchEntry.

        Args:
            row: Dictionary of CSV column values

        Returns:
            PrefetchEntry object, or None if row is invalid
        """
        try:
            # Parse basic metadata
            source_filename = row.get('SourceFilename', '')
            executable = row.get('Executable', '')
            run_count = int(row.get('RunCount', 0))
            hash_value = row.get('Hash', '')
            volume_name = row.get('Volume0Name', '')
            volume_serial = row.get('Volume0Serial', '')

            # Parse last run time
            last_run_time = self._parse_timestamp(row.get('LastRunTime'))

            # Parse previous run times (PreviousRunTime0 through PreviousRunTime6)
            previous_run_times = []
            for i in range(7):
                prev_time = self._parse_timestamp(row.get(f'PreviousRunTime{i}'))
                if prev_time:
                    previous_run_times.append(prev_time)

            # Parse files loaded (comma-separated list)
            files_loaded_str = row.get('FilesLoaded', '')
            files_loaded = [f.strip() for f in files_loaded_str.split(',') if f.strip()]

            return PrefetchEntry(
                source_filename=source_filename,
                executable=executable,
                run_count=run_count,
                last_run_time=last_run_time,
                previous_run_times=previous_run_times,
                files_loaded=files_loaded,
                volume_name=volume_name or None,
                volume_serial=volume_serial or None,
                hash_value=hash_value or None
            )

        except Exception as e:
            # Log error and skip invalid row
            logger.warning(f"Failed to parse Prefetch row: {e}")
            return None

    def _parse_timestamp(self, timestamp_str: Optional[str]) -> Optional[datetime]:
        """
        Parse timestamp string to datetime.

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

            return dt
        except Exception:
            return None

    def find_by_executable(self, entries: List[PrefetchEntry], executable_name: str,
                          case_sensitive: bool = False) -> List[PrefetchEntry]:
        """
        Find Prefetch entries by executable name.

        Args:
            entries: List of Prefetch entries to search
            executable_name: Executable name to search for (e.g., "malware.exe")
            case_sensitive: Whether search should be case-sensitive

        Returns:
            List of matching Prefetch entries
        """
        if case_sensitive:
            return [e for e in entries if e.executable == executable_name]
        else:
            exe_lower = executable_name.lower()
            return [e for e in entries if e.executable.lower() == exe_lower]

    def find_by_dll_loaded(self, entries: List[PrefetchEntry], dll_name: str,
                          case_sensitive: bool = False) -> List[PrefetchEntry]:
        """
        Find executables that loaded a specific DLL.

        Args:
            entries: List of Prefetch entries to search
            dll_name: DLL name to search for
            case_sensitive: Whether search should be case-sensitive

        Returns:
            List of Prefetch entries that loaded the DLL
        """
        matches = []

        for entry in entries:
            if case_sensitive:
                if any(dll_name in f for f in entry.files_loaded):
                    matches.append(entry)
            else:
                dll_lower = dll_name.lower()
                if any(dll_lower in f.lower() for f in entry.files_loaded):
                    matches.append(entry)

        return matches

    def get_most_recent_executions(self, entries: List[PrefetchEntry],
                                  limit: int = 10) -> List[PrefetchEntry]:
        """
        Get most recently executed programs.

        Args:
            entries: List of Prefetch entries
            limit: Maximum number of entries to return

        Returns:
            List of entries sorted by last run time (newest first)
        """
        # Filter entries with valid last_run_time
        valid_entries = [e for e in entries if e.last_run_time]

        # Sort by last_run_time descending
        sorted_entries = sorted(valid_entries,
                              key=lambda e: e.last_run_time,
                              reverse=True)

        return sorted_entries[:limit]

    def get_frequently_run(self, entries: List[PrefetchEntry],
                          min_run_count: int = 10) -> List[PrefetchEntry]:
        """
        Get frequently executed programs.

        Args:
            entries: List of Prefetch entries
            min_run_count: Minimum run count threshold

        Returns:
            List of entries with run_count >= min_run_count, sorted by count
        """
        frequent = [e for e in entries if e.run_count >= min_run_count]

        # Sort by run_count descending
        return sorted(frequent, key=lambda e: e.run_count, reverse=True)

    def correlate_with_mft(self, prefetch_entry: PrefetchEntry,
                          mft_entries: List,
                          comparator: TimestampComparator) -> Optional[dict]:
        """
        Correlate Prefetch execution with MFT file timestamps.

        Args:
            prefetch_entry: Prefetch entry to correlate
            mft_entries: List of MFT entries (from mft_parser)
            comparator: TimestampComparator instance

        Returns:
            Dict with correlation results, or None if no MFT entry found
        """
        # Find matching MFT entry by executable name
        executable_name = prefetch_entry.executable

        matching_mft = []
        for mft_entry in mft_entries:
            if mft_entry.file_name.lower() == executable_name.lower():
                matching_mft.append(mft_entry)

        if not matching_mft:
            return None

        # Use the first match (could be multiple if file moved/renamed)
        mft_entry = matching_mft[0]

        # Compare timestamps
        mft_modified = mft_entry.get_modification_time(prefer_fn=True)
        prefetch_last_run = prefetch_entry.last_run_time

        if not mft_modified or not prefetch_last_run:
            return None

        # Detect causality violation
        violation = comparator.detect_causality_violation(mft_modified, prefetch_last_run)

        return {
            'mft_entry': mft_entry,
            'prefetch_entry': prefetch_entry,
            'mft_modified': mft_modified,
            'prefetch_last_run': prefetch_last_run,
            'time_delta_seconds': comparator.time_delta_seconds(mft_modified, prefetch_last_run),
            'causality_violation': violation
        }
