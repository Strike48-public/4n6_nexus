"""
Timestamp comparison and validation utilities.

Handles timestamp parsing from multiple forensic tools with different formats,
precision levels, and timezone handling.
"""

from datetime import datetime, timedelta
from dateutil import parser
import pytz
from typing import Optional, Tuple


class TimestampComparator:
    """
    Utility class for comparing timestamps from forensic tools
    with tolerance windows and null handling.
    """

    # Windows FILETIME epoch (1601-01-01 00:00:00 UTC)
    WINDOWS_EPOCH = datetime(1601, 1, 1, tzinfo=pytz.utc)

    # Unix epoch (1970-01-01 00:00:00 UTC)
    UNIX_EPOCH = datetime(1970, 1, 1, tzinfo=pytz.utc)

    def __init__(self, default_tolerance_seconds: int = 300):
        """
        Initialize comparator with default tolerance window.

        Args:
            default_tolerance_seconds: Default tolerance for timestamp comparison (5 minutes)
        """
        self.default_tolerance = default_tolerance_seconds

    def parse_iso8601(self, timestamp_str: str) -> datetime:
        """
        Parse any ISO 8601 timestamp to UTC datetime.

        Handles various precision levels:
        - 2025-03-15T14:23:45Z
        - 2025-03-15T14:23:45.123456Z
        - 2025-03-15T14:23:45.1234567Z

        Args:
            timestamp_str: ISO 8601 formatted timestamp string

        Returns:
            Timezone-aware datetime in UTC

        Raises:
            ValueError: If timestamp cannot be parsed
        """
        try:
            dt = parser.isoparse(timestamp_str)

            # Ensure UTC
            if dt.tzinfo is None:
                dt = pytz.utc.localize(dt)
            else:
                dt = dt.astimezone(pytz.utc)

            return dt
        except Exception as e:
            raise ValueError(f"Failed to parse timestamp '{timestamp_str}': {e}")

    def is_null(self, dt: datetime) -> bool:
        """
        Check if timestamp is null/epoch.

        Args:
            dt: Datetime to check

        Returns:
            True if timestamp is Windows or Unix epoch (null value)
        """
        return dt == self.WINDOWS_EPOCH or dt == self.UNIX_EPOCH

    def compare(
        self,
        dt1: datetime,
        dt2: datetime,
        tolerance_seconds: Optional[int] = None
    ) -> Optional[int]:
        """
        Compare two timestamps with tolerance window.

        Args:
            dt1: First datetime
            dt2: Second datetime
            tolerance_seconds: Comparison tolerance (uses default if None)

        Returns:
            None: One or both timestamps are null
            0: Timestamps within tolerance (equivalent)
            -1: dt1 is earlier than dt2 (beyond tolerance)
            +1: dt1 is later than dt2 (beyond tolerance)
        """
        if self.is_null(dt1) or self.is_null(dt2):
            return None

        tolerance = tolerance_seconds if tolerance_seconds is not None else self.default_tolerance
        diff = (dt1 - dt2).total_seconds()

        if abs(diff) <= tolerance:
            return 0
        elif diff < 0:
            return -1
        else:
            return +1

    def time_delta_seconds(self, dt1: datetime, dt2: datetime) -> Optional[float]:
        """
        Calculate time difference in seconds.

        Args:
            dt1: First datetime
            dt2: Second datetime

        Returns:
            Seconds between timestamps (positive if dt1 > dt2), or None if either is null
        """
        if self.is_null(dt1) or self.is_null(dt2):
            return None

        return (dt1 - dt2).total_seconds()

    def detect_causality_violation(
        self,
        file_modified: datetime,
        process_executed: datetime,
        tolerance_seconds: int = 300
    ) -> Optional[dict]:
        """
        Detect if file was modified AFTER it was executed.

        This is a causality violation - you cannot run a file that doesn't exist yet.

        Args:
            file_modified: Datetime from MFT $SI or $FN
            process_executed: Datetime from Prefetch or Event Log
            tolerance_seconds: Grace period for timing skew (default 5 minutes)

        Returns:
            Dict with violation details, or None if no violation
        """
        comparison = self.compare(file_modified, process_executed, tolerance_seconds)

        if comparison is None:
            return None  # Cannot determine (null timestamp)

        if comparison > 0:
            # file_modified > process_executed = VIOLATION
            time_delta = self.time_delta_seconds(file_modified, process_executed)
            return {
                'type': 'causality_violation',
                'description': f"File modified at {file_modified} but executed at {process_executed}",
                'file_modified_time': file_modified,
                'process_executed_time': process_executed,
                'time_delta_seconds': time_delta,
                'severity': 'high' if time_delta > 600 else 'medium'
            }

        return None  # No violation

    def detect_timestomping(
        self,
        si_modified: datetime,
        fn_modified: datetime,
        tolerance_seconds: int = 60
    ) -> Optional[dict]:
        """
        Detect timestamp manipulation by comparing $STANDARD_INFORMATION vs $FILE_NAME.

        $SI timestamps can be modified with SetFileTime API.
        $FN timestamps require MFT record modification (harder to tamper).

        If $SI time is EARLIER than $FN time (beyond tolerance), timestomping likely occurred.

        Args:
            si_modified: $STANDARD_INFORMATION modified time
            fn_modified: $FILE_NAME modified time
            tolerance_seconds: Grace period for legitimate differences (default 1 minute)

        Returns:
            Dict with timestomping details, or None if no tampering detected
        """
        if self.is_null(si_modified) or self.is_null(fn_modified):
            return None

        time_delta = self.time_delta_seconds(si_modified, fn_modified)

        if time_delta < -tolerance_seconds:
            # $SI is earlier than $FN (beyond tolerance) = TIMESTOMPING
            return {
                'type': 'timestomping_detected',
                'description': f"$SI timestamp ({si_modified}) is earlier than $FN timestamp ({fn_modified})",
                'si_modified': si_modified,
                'fn_modified': fn_modified,
                'time_delta_seconds': time_delta,
                'severity': 'critical'
            }

        return None  # No timestomping detected

    def format_timestamp(self, dt: datetime, include_microseconds: bool = True) -> str:
        """
        Format datetime for logging and output.

        Args:
            dt: Datetime to format
            include_microseconds: Include microseconds in output

        Returns:
            ISO 8601 formatted string in UTC
        """
        if self.is_null(dt):
            return "NULL"

        if include_microseconds:
            return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        else:
            return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
