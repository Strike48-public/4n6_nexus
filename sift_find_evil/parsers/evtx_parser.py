"""Event Log Parser - Parse EvtxECmd CSV output.

Extracts security events for tiebreaker validation.
"""

import csv
import logging
from dataclasses import dataclass
from datetime import datetime
from typing import List, Optional
from pathlib import Path

from ..validators.timestamp_comparator import TimestampComparator

logger = logging.getLogger(__name__)


@dataclass
class EventLogEntry:
    """Represents a single Windows Event Log entry."""
    time_created: datetime
    event_id: int
    record_id: int
    computer: str
    channel: str  # Security, System, Application, etc.
    level: str  # Information, Warning, Error, Critical
    user_id: Optional[str] = None

    # Event-specific payload data (extracted by Maps)
    payload_data1: Optional[str] = None  # Often: Process Name or Object Name
    payload_data2: Optional[str] = None
    payload_data3: Optional[str] = None
    payload_data4: Optional[str] = None
    payload_data5: Optional[str] = None
    payload_data6: Optional[str] = None  # Often: Command Line

    map_description: Optional[str] = None

    # Event IDs that represent process creation across Windows generations.
    # 4688 = Vista+. 592 = XP / Windows Server 2003 / NT classic Security log.
    PROCESS_CREATION_EVENT_IDS = (4688, 592)

    def is_process_creation(self) -> bool:
        """Check if this is a process creation event.

        Returns:
            True if event_id is 4688 (Vista+) or 592 (Windows XP/Server 2003).
        """
        return self.event_id in self.PROCESS_CREATION_EVENT_IDS

    def get_process_name(self) -> Optional[str]:
        """Extract process name for a process-creation event (4688 / 592).

        Returns:
            Full process path, or None if not available.
        """
        if self.is_process_creation() and self.payload_data1:
            return self.payload_data1
        return None

    def get_command_line(self) -> Optional[str]:
        """Extract command line for a process-creation event.

        Windows XP Event 592 does not include a command line; only 4688 does.

        Returns:
            Command line string, or None if not available.
        """
        if self.is_process_creation() and self.payload_data6:
            return self.payload_data6
        return None

    def get_executable_name(self) -> Optional[str]:
        """Extract just the executable filename from process path.

        Returns:
            Executable name (e.g., "malware.exe"), or None.
        """
        process_path = self.get_process_name()
        if not process_path:
            return None

        # Extract filename from path (handle both \ and /)
        if '\\' in process_path:
            return process_path.split('\\')[-1]
        elif '/' in process_path:
            return process_path.split('/')[-1]
        else:
            return process_path


class EventLogParser:
    """Parser for EvtxECmd CSV output.

    Reads Event Log entries for validation and tiebreaker analysis.
    """

    def __init__(self):
        """Initialize the parser with a timestamp comparator."""
        self.comparator = TimestampComparator()

    def parse_csv(self, csv_path: str, filter_event_ids: Optional[List[int]] = None) -> List[EventLogEntry]:
        """Parse EvtxECmd CSV file.

        Args:
            csv_path: Path to parsed event log CSV
            filter_event_ids: Optional list of Event IDs to filter (e.g., [4688])

        Returns:
            List of EventLogEntry objects

        Raises:
            FileNotFoundError: If CSV file doesn't exist
            ValueError: If CSV format is invalid
        """
        csv_file = Path(csv_path)
        if not csv_file.exists():
            raise FileNotFoundError(f"Event Log CSV not found: {csv_path}")

        entries = []

        with open(csv_file, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)

            for row in reader:
                entry = self._parse_row(row)
                if entry:
                    # Apply event ID filter if specified
                    if filter_event_ids is None or entry.event_id in filter_event_ids:
                        entries.append(entry)

        return entries

    def _parse_row(self, row: dict) -> Optional[EventLogEntry]:
        """Parse a single CSV row into an EventLogEntry.

        Args:
            row: Dictionary of CSV column values

        Returns:
            EventLogEntry object, or None if row is invalid
        """
        try:
            # Parse required fields
            time_created = self._parse_timestamp(row.get('TimeCreated'))
            if not time_created:
                return None  # Skip entries without timestamp

            event_id = int(row.get('EventId', 0))
            record_id = int(row.get('RecordId', 0))
            computer = row.get('Computer', '')
            channel = row.get('Channel', '')
            level = row.get('Level', '')

            # Parse optional fields
            user_id = row.get('UserId') or None
            map_description = row.get('MapDescription') or None

            # Parse payload data (Maps-extracted fields)
            payload_data1 = row.get('PayloadData1') or None
            payload_data2 = row.get('PayloadData2') or None
            payload_data3 = row.get('PayloadData3') or None
            payload_data4 = row.get('PayloadData4') or None
            payload_data5 = row.get('PayloadData5') or None
            payload_data6 = row.get('PayloadData6') or None

            return EventLogEntry(
                time_created=time_created,
                event_id=event_id,
                record_id=record_id,
                computer=computer,
                channel=channel,
                level=level,
                user_id=user_id,
                payload_data1=payload_data1,
                payload_data2=payload_data2,
                payload_data3=payload_data3,
                payload_data4=payload_data4,
                payload_data5=payload_data5,
                payload_data6=payload_data6,
                map_description=map_description
            )

        except Exception as e:
            # Log error and skip invalid row
            logger.warning(f"Failed to parse Event Log row: {e}")
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

            return dt
        except Exception:
            return None

    def get_process_creation_events(self, entries: List[EventLogEntry]) -> List[EventLogEntry]:
        """Filter to process-creation events across Windows generations.

        Matches Event ID 4688 (Vista+) and 592 (XP / Server 2003).

        Args:
            entries: List of event log entries to filter.

        Returns:
            Filtered list containing only process creation events.
        """
        return [e for e in entries if e.is_process_creation()]

    def find_by_executable(self, entries: List[EventLogEntry], executable_name: str,
                          case_sensitive: bool = False) -> List[EventLogEntry]:
        """Find events for a specific executable.

        Args:
            entries: List of event log entries
            executable_name: Executable name to search for (e.g., "malware.exe")
            case_sensitive: Whether search should be case-sensitive

        Returns:
            List of matching events
        """
        matches = []

        for entry in entries:
            exe_name = entry.get_executable_name()
            if not exe_name:
                continue

            if case_sensitive:
                if exe_name == executable_name:
                    matches.append(entry)
            else:
                if exe_name.lower() == executable_name.lower():
                    matches.append(entry)

        return matches

    def find_by_time_window(self, entries: List[EventLogEntry],
                           target_time: datetime,
                           tolerance_seconds: int = 300) -> List[EventLogEntry]:
        """Find events within a time window.

        Args:
            entries: List of event log entries
            target_time: Target datetime to search around
            tolerance_seconds: Time window in seconds (±tolerance)

        Returns:
            List of events within the time window
        """
        matches = []

        for entry in entries:
            comparison = self.comparator.compare(
                entry.time_created,
                target_time,
                tolerance_seconds
            )

            if comparison == 0:  # Within tolerance
                matches.append(entry)

        return matches

    def resolve_contradiction(self, executable_name: str,
                            prefetch_time: datetime,
                            mft_time: datetime,
                            entries: List[EventLogEntry],
                            tolerance_seconds: int = 300) -> dict:
        """Use process-creation events (4688 or 592) as MFT vs Prefetch tiebreaker.

        Args:
            executable_name: Name of executable to search for
            prefetch_time: Prefetch last run time
            mft_time: MFT modification time
            entries: List of Event Log entries (should be filtered to 4688)
            tolerance_seconds: Search window around prefetch_time

        Returns:
            Dict with resolution results
        """
        # Find Event ID 4688 entries for this executable
        process_events = self.get_process_creation_events(entries)
        exe_events = self.find_by_executable(process_events, executable_name)

        if not exe_events:
            return {
                'resolution': 'uncertain_no_event_log',
                'confidence_recovery': 0.0,
                'reasoning': f'No Event ID 4688 found for {executable_name}',
                'event_count': 0
            }

        # Find events within tolerance of Prefetch time
        matching_events = self.find_by_time_window(
            exe_events,
            prefetch_time,
            tolerance_seconds
        )

        if matching_events:
            # Event Log confirms Prefetch time
            closest_event = min(
                matching_events,
                key=lambda e: abs(self.comparator.time_delta_seconds(e.time_created, prefetch_time) or float('inf'))
            )

            time_delta = self.comparator.time_delta_seconds(
                closest_event.time_created,
                prefetch_time
            )

            return {
                'resolution': 'event_log_confirms_prefetch',
                'ground_truth_time': closest_event.time_created,
                'confidence_recovery': 0.30,  # Recover 30% confidence
                'reasoning': f'Event ID 4688 confirms execution at {closest_event.time_created}, '
                           f'aligning with Prefetch (Δ{time_delta:.1f}s)',
                'event_count': len(matching_events),
                'closest_event': closest_event
            }
        else:
            # Events found but not within tolerance window
            return {
                'resolution': 'event_log_mismatch',
                'confidence_recovery': 0.0,
                'reasoning': f'Found {len(exe_events)} Event ID 4688 entries but none within '
                           f'±{tolerance_seconds}s of Prefetch time',
                'event_count': len(exe_events),
                'all_event_times': [e.time_created for e in exe_events]
            }

    def get_events_by_id(self, entries: List[EventLogEntry], event_id: int) -> List[EventLogEntry]:
        """Filter events by Event ID.

        Args:
            entries: List of event log entries
            event_id: Event ID to filter (e.g., 4688, 4624, 4689)

        Returns:
            List of matching events
        """
        return [e for e in entries if e.event_id == event_id]

    def get_timeline(self, entries: List[EventLogEntry],
                    start_time: Optional[datetime] = None,
                    end_time: Optional[datetime] = None) -> List[EventLogEntry]:
        """Get events within a time range.

        Args:
            entries: List of event log entries
            start_time: Start of time range (inclusive)
            end_time: End of time range (inclusive)

        Returns:
            List of events sorted by timestamp
        """
        filtered = entries

        if start_time:
            filtered = [e for e in filtered if e.time_created >= start_time]

        if end_time:
            filtered = [e for e in filtered if e.time_created <= end_time]

        # Sort by timestamp
        return sorted(filtered, key=lambda e: e.time_created)
