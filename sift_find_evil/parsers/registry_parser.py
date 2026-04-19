"""Windows Registry Parser - Parse execution evidence and persistence artifacts.

Extracts execution evidence (Shimcache, Amcache, BAM/DAM) and persistence
mechanisms (Run keys, Services) from Windows Registry hives for detection
when Prefetch files are deleted or unavailable.
"""

import csv
import logging
import struct
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ShimcacheEntry:
    """Shimcache execution evidence from SYSTEM hive.

    Shimcache (Application Compatibility Cache) records file execution metadata
    even when Prefetch is deleted. Located at:
    SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCompatCache

    Attributes:
        file_path: Full path to executed file
        last_modified: File's last modification time
        file_size: Size of executable in bytes
        exec_flag: Whether file was executed (Windows 10+)
    """

    file_path: str
    last_modified: datetime
    file_size: int
    exec_flag: Optional[bool] = None  # None for older Windows versions

    def __post_init__(self):
        """Validate shimcache entry."""
        if not self.file_path:
            raise ValueError("File path cannot be empty")


@dataclass(frozen=True)
class AmcacheEntry:
    """Amcache execution evidence from Amcache.hve.

    Amcache records first execution time and SHA-1 hash for installed applications.
    Located at: C:\\Windows\\appcompat\\Programs\\Amcache.hve

    Attributes:
        file_path: Full path to executed file
        first_execution: When file was first executed
        sha1_hash: SHA-1 hash of the executable
        file_size: Size of executable in bytes
        publisher: Software publisher (if available)
    """

    file_path: str
    first_execution: datetime
    sha1_hash: str
    file_size: int
    publisher: Optional[str] = None

    def __post_init__(self):
        """Validate amcache entry."""
        if not self.file_path:
            raise ValueError("File path cannot be empty")
        if not self.sha1_hash or len(self.sha1_hash) != 40:
            raise ValueError("SHA-1 hash must be 40 hexadecimal characters")


@dataclass(frozen=True)
class BAMEntry:
    """Background Activity Moderator (BAM) or Desktop Activity Moderator (DAM) entry.

    BAM/DAM records process execution timestamps with microsecond precision.
    Located at: SYSTEM\\CurrentControlSet\\Services\\bam\\State\\UserSettings (Windows 10+)

    Attributes:
        file_path: Full path to executed file
        execution_time: When process was executed (microsecond precision)
        user_sid: Security Identifier of user who executed the process
    """

    file_path: str
    execution_time: datetime
    user_sid: str

    def __post_init__(self):
        """Validate BAM entry."""
        if not self.file_path:
            raise ValueError("File path cannot be empty")
        if not self.user_sid:
            raise ValueError("User SID cannot be empty")


@dataclass(frozen=True)
class UserAssistEntry:
    """UserAssist GUI program execution evidence from NTUSER.DAT.

    UserAssist records GUI program executions via shell (Explorer).
    Located at: NTUSER.DAT\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist

    Attributes:
        program_name: Executable name (ROT-13 encoded in registry)
        run_count: Number of times executed
        last_execution: When program was last run
        focus_count: Number of times window received focus
        focus_time_ms: Total milliseconds window had focus
    """

    program_name: str
    run_count: int
    last_execution: datetime
    focus_count: int = 0
    focus_time_ms: int = 0

    def __post_init__(self):
        """Validate UserAssist entry."""
        if not self.program_name:
            raise ValueError("Program name cannot be empty")


@dataclass(frozen=True)
class RunKeyEntry:
    """Persistence via Run key from SOFTWARE or NTUSER.DAT hive.

    Run keys execute programs at user logon or system startup.
    Locations:
    - HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run
    - HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run

    Attributes:
        key_path: Full registry key path
        value_name: Name of the registry value
        command: Command line to execute
        hive: Registry hive ("HKLM" or "HKCU")
        last_write_time: When registry key was last modified
    """

    key_path: str
    value_name: str
    command: str
    hive: str  # "HKLM" or "HKCU"
    last_write_time: datetime

    def __post_init__(self):
        """Validate Run key entry."""
        if self.hive not in ("HKLM", "HKCU"):
            raise ValueError(f"Invalid hive: {self.hive}")
        if not self.command:
            raise ValueError("Command cannot be empty")


class RegistryParser:
    """Parse Windows Registry artifacts for execution evidence and persistence.

    Supports:
    - Shimcache (SYSTEM hive) - Execution evidence even when Prefetch deleted
    - Amcache (Amcache.hve) - First execution time + SHA-1 hashes
    - BAM/DAM (SYSTEM hive) - Process execution timestamps (microsecond precision)
    - UserAssist (NTUSER.DAT) - GUI program usage
    - Run keys (SOFTWARE, NTUSER.DAT) - Persistence mechanisms

    Note: This parser reads CSV exports from tools like RegRipper or Registry Explorer.
    Future enhancement: Direct registry hive parsing with python-registry library.
    """

    def parse_shimcache_csv(self, csv_path: Path) -> list[ShimcacheEntry]:
        """Parse Shimcache from CSV export.

        CSV format (from RegRipper or RECmd):
            file_path,last_modified,file_size,exec_flag
            C:\\Windows\\System32\\cmd.exe,2025-03-15 10:30:00,123456,True

        Args:
            csv_path: Path to Shimcache CSV file

        Returns:
            List of Shimcache entries

        Raises:
            FileNotFoundError: If CSV file doesn't exist
            ValueError: If CSV format is invalid

        Example:
            >>> parser = RegistryParser()
            >>> entries = parser.parse_shimcache_csv(Path("shimcache.csv"))
            >>> print(f"Found {len(entries)} shimcache entries")
        """
        if not csv_path.exists():
            raise FileNotFoundError(f"Shimcache CSV not found: {csv_path}")

        entries = []

        try:
            with csv_path.open("r", encoding="utf-8") as f:
                reader = csv.DictReader(f)

                for row in reader:
                    # Parse timestamp
                    last_modified = datetime.fromisoformat(
                        row["last_modified"].replace(" ", "T")
                    )
                    if last_modified.tzinfo is None:
                        last_modified = last_modified.replace(tzinfo=timezone.utc)

                    # Parse exec flag (may be empty string for older Windows)
                    exec_flag_str = row.get("exec_flag", "").strip()
                    exec_flag = None
                    if exec_flag_str:
                        exec_flag = exec_flag_str.lower() in ("true", "1", "yes")

                    entries.append(ShimcacheEntry(
                        file_path=row["file_path"],
                        last_modified=last_modified,
                        file_size=int(row["file_size"]),
                        exec_flag=exec_flag
                    ))

            logger.info(f"Parsed {len(entries)} Shimcache entries from {csv_path}")

        except (KeyError, ValueError) as e:
            logger.error(f"Invalid Shimcache CSV format in {csv_path}: {e}")
            raise ValueError(f"Invalid Shimcache CSV format: {e}")

        return entries

    def parse_amcache_csv(self, csv_path: Path) -> list[AmcacheEntry]:
        """Parse Amcache from CSV export.

        CSV format (from RECmd or AmcacheParser):
            file_path,first_execution,sha1_hash,file_size,publisher
            C:\\Program Files\\app.exe,2025-03-15 10:30:00,abc123...,123456,Publisher Name

        Args:
            csv_path: Path to Amcache CSV file

        Returns:
            List of Amcache entries

        Raises:
            FileNotFoundError: If CSV file doesn't exist
            ValueError: If CSV format is invalid

        Example:
            >>> parser = RegistryParser()
            >>> entries = parser.parse_amcache_csv(Path("amcache.csv"))
            >>> for entry in entries:
            ...     print(f"{entry.file_path}: {entry.sha1_hash}")
        """
        if not csv_path.exists():
            raise FileNotFoundError(f"Amcache CSV not found: {csv_path}")

        entries = []

        try:
            with csv_path.open("r", encoding="utf-8") as f:
                reader = csv.DictReader(f)

                for row in reader:
                    # Parse timestamp
                    first_execution = datetime.fromisoformat(
                        row["first_execution"].replace(" ", "T")
                    )
                    if first_execution.tzinfo is None:
                        first_execution = first_execution.replace(tzinfo=timezone.utc)

                    # Publisher may be empty
                    publisher = row.get("publisher", "").strip() or None

                    entries.append(AmcacheEntry(
                        file_path=row["file_path"],
                        first_execution=first_execution,
                        sha1_hash=row["sha1_hash"].lower(),
                        file_size=int(row["file_size"]),
                        publisher=publisher
                    ))

            logger.info(f"Parsed {len(entries)} Amcache entries from {csv_path}")

        except (KeyError, ValueError) as e:
            logger.error(f"Invalid Amcache CSV format in {csv_path}: {e}")
            raise ValueError(f"Invalid Amcache CSV format: {e}")

        return entries

    def parse_bam_csv(self, csv_path: Path) -> list[BAMEntry]:
        """Parse BAM/DAM from CSV export.

        CSV format (from RECmd or custom parser):
            file_path,execution_time,user_sid
            C:\\Windows\\System32\\cmd.exe,2025-03-15 10:30:00.123456,S-1-5-21-...

        Args:
            csv_path: Path to BAM CSV file

        Returns:
            List of BAM entries

        Raises:
            FileNotFoundError: If CSV file doesn't exist
            ValueError: If CSV format is invalid

        Example:
            >>> parser = RegistryParser()
            >>> entries = parser.parse_bam_csv(Path("bam.csv"))
            >>> for entry in entries:
            ...     print(f"{entry.file_path} executed at {entry.execution_time}")
        """
        if not csv_path.exists():
            raise FileNotFoundError(f"BAM CSV not found: {csv_path}")

        entries = []

        try:
            with csv_path.open("r", encoding="utf-8") as f:
                reader = csv.DictReader(f)

                for row in reader:
                    # Parse timestamp with microsecond precision
                    execution_time = datetime.fromisoformat(
                        row["execution_time"].replace(" ", "T")
                    )
                    if execution_time.tzinfo is None:
                        execution_time = execution_time.replace(tzinfo=timezone.utc)

                    entries.append(BAMEntry(
                        file_path=row["file_path"],
                        execution_time=execution_time,
                        user_sid=row["user_sid"]
                    ))

            logger.info(f"Parsed {len(entries)} BAM entries from {csv_path}")

        except (KeyError, ValueError) as e:
            logger.error(f"Invalid BAM CSV format in {csv_path}: {e}")
            raise ValueError(f"Invalid BAM CSV format: {e}")

        return entries

    def parse_userassist_csv(self, csv_path: Path) -> list[UserAssistEntry]:
        """Parse UserAssist from CSV export.

        CSV format (from RECmd or custom parser):
            program_name,run_count,last_execution,focus_count,focus_time_ms
            notepad.exe,5,2025-03-15 10:30:00,3,12500

        Args:
            csv_path: Path to UserAssist CSV file

        Returns:
            List of UserAssist entries

        Raises:
            FileNotFoundError: If CSV file doesn't exist
            ValueError: If CSV format is invalid

        Example:
            >>> parser = RegistryParser()
            >>> entries = parser.parse_userassist_csv(Path("userassist.csv"))
            >>> for entry in entries:
            ...     print(f"{entry.program_name} run {entry.run_count} times")
        """
        if not csv_path.exists():
            raise FileNotFoundError(f"UserAssist CSV not found: {csv_path}")

        entries = []

        try:
            with csv_path.open("r", encoding="utf-8") as f:
                reader = csv.DictReader(f)

                for row in reader:
                    # Parse timestamp
                    last_execution = datetime.fromisoformat(
                        row["last_execution"].replace(" ", "T")
                    )
                    if last_execution.tzinfo is None:
                        last_execution = last_execution.replace(tzinfo=timezone.utc)

                    entries.append(UserAssistEntry(
                        program_name=row["program_name"],
                        run_count=int(row["run_count"]),
                        last_execution=last_execution,
                        focus_count=int(row.get("focus_count", 0)),
                        focus_time_ms=int(row.get("focus_time_ms", 0))
                    ))

            logger.info(f"Parsed {len(entries)} UserAssist entries from {csv_path}")

        except (KeyError, ValueError) as e:
            logger.error(f"Invalid UserAssist CSV format in {csv_path}: {e}")
            raise ValueError(f"Invalid UserAssist CSV format: {e}")

        return entries

    def parse_run_keys_csv(self, csv_path: Path) -> list[RunKeyEntry]:
        """Parse Run keys from CSV export.

        CSV format (from RECmd or RegRipper):
            key_path,value_name,command,hive,last_write_time
            Software\\Microsoft\\Windows\\CurrentVersion\\Run,Malware,C:\\evil.exe,HKLM,2025-03-15 10:30:00

        Args:
            csv_path: Path to Run keys CSV file

        Returns:
            List of Run key entries

        Raises:
            FileNotFoundError: If CSV file doesn't exist
            ValueError: If CSV format is invalid

        Example:
            >>> parser = RegistryParser()
            >>> entries = parser.parse_run_keys_csv(Path("run_keys.csv"))
            >>> for entry in entries:
            ...     if "suspicious" in entry.command.lower():
            ...         print(f"Suspicious: {entry.command}")
        """
        if not csv_path.exists():
            raise FileNotFoundError(f"Run keys CSV not found: {csv_path}")

        entries = []

        try:
            with csv_path.open("r", encoding="utf-8") as f:
                reader = csv.DictReader(f)

                for row in reader:
                    # Parse timestamp
                    last_write_time = datetime.fromisoformat(
                        row["last_write_time"].replace(" ", "T")
                    )
                    if last_write_time.tzinfo is None:
                        last_write_time = last_write_time.replace(tzinfo=timezone.utc)

                    entries.append(RunKeyEntry(
                        key_path=row["key_path"],
                        value_name=row["value_name"],
                        command=row["command"],
                        hive=row["hive"],
                        last_write_time=last_write_time
                    ))

            logger.info(f"Parsed {len(entries)} Run key entries from {csv_path}")

        except (KeyError, ValueError) as e:
            logger.error(f"Invalid Run keys CSV format in {csv_path}: {e}")
            raise ValueError(f"Invalid Run keys CSV format: {e}")

        return entries
