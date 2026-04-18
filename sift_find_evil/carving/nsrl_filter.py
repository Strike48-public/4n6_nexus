"""NSRL (National Software Reference Library) hash filtering.

Provides known-good file filtering for carved file analysis. NSRL is a NIST-
maintained database of software hashes from legitimate commercial applications,
operating systems, and tools.

Usage:
    filter = NSRLFilter("/path/to/NSRLFile.txt")
    if filter.is_known_good("abc123..."):
        # File is known-good system file
    else:
        # File is unknown, requires investigation

NSRL RDS (Reference Data Set) structure:
- NSRLFile.txt: Main hash database (SHA-1, MD5, CRC32, filename, size)
- Format: "SHA-1","MD5","CRC32","FileName","FileSize","ProductCode","OpSystemCode","SpecialCode"

Performance:
- In-memory hash set: O(1) lookup, ~2-3 GB RAM for Modern RDS
- First load: 30-60 seconds (parsing CSV, building hash set)
- Subsequent lookups: <1 microsecond per hash

Storage requirements:
- Modern RDS: 8-12 GB on disk, 2-3 GB in RAM
- Full RDS: 30-50 GB on disk, 8-10 GB in RAM
"""

from __future__ import annotations

import csv
import logging
from pathlib import Path
from typing import Set

logger = logging.getLogger(__name__)


class NSRLFilter:
    """NSRL hash filter for known-good file identification.

    Loads NSRL RDS database and provides fast hash lookup for filtering
    legitimate system files during carved file analysis.

    Attributes:
        nsrl_path: Path to NSRLFile.txt
        sha1_hashes: Set of SHA-1 hashes (NSRL primary index)
        md5_hashes: Set of MD5 hashes (for compatibility)
        loaded: Whether database is loaded in memory
    """

    def __init__(self, nsrl_path: str | Path):
        """Initialize NSRL filter.

        Args:
            nsrl_path: Path to NSRLFile.txt from NSRL RDS

        Raises:
            FileNotFoundError: If NSRLFile.txt not found
        """
        self.nsrl_path = Path(nsrl_path)
        if not self.nsrl_path.exists():
            raise FileNotFoundError(
                f"NSRL database not found: {self.nsrl_path}\n"
                f"Run: ./scripts/download-nsrl.sh modern"
            )

        self.sha1_hashes: Set[str] = set()
        self.md5_hashes: Set[str] = set()
        self.loaded = False

    def load(self) -> None:
        """Load NSRL database into memory.

        Parses NSRLFile.txt and builds in-memory hash sets for fast lookup.
        This is a one-time operation (30-60 seconds for Modern RDS).

        CSV format:
        "SHA-1","MD5","CRC32","FileName","FileSize","ProductCode","OpSystemCode","SpecialCode"

        Raises:
            ValueError: If NSRLFile.txt format is invalid
        """
        if self.loaded:
            logger.debug("NSRL database already loaded")
            return

        logger.info(f"Loading NSRL database: {self.nsrl_path}")
        logger.info("This may take 30-60 seconds...")

        try:
            with open(self.nsrl_path, "r", encoding="utf-8", errors="ignore") as f:
                reader = csv.DictReader(f)

                # Validate header
                expected_fields = {"SHA-1", "MD5"}
                if not expected_fields.issubset(reader.fieldnames or []):
                    raise ValueError(
                        f"Invalid NSRL format. Expected fields: {expected_fields}, "
                        f"found: {reader.fieldnames}"
                    )

                # Load hashes
                count = 0
                for row in reader:
                    sha1 = row.get("SHA-1", "").strip().lower()
                    md5 = row.get("MD5", "").strip().lower()

                    if sha1:
                        self.sha1_hashes.add(sha1)
                    if md5:
                        self.md5_hashes.add(md5)

                    count += 1
                    if count % 1_000_000 == 0:
                        logger.info(f"Loaded {count:,} entries...")

            self.loaded = True
            logger.info(
                f"NSRL database loaded: {len(self.sha1_hashes):,} SHA-1 hashes, "
                f"{len(self.md5_hashes):,} MD5 hashes"
            )

        except Exception as e:
            logger.error(f"Failed to load NSRL database: {e}")
            raise

    def is_known_good(self, file_hash: str, hash_type: str = "sha1") -> bool:
        """Check if file hash is in NSRL database.

        Args:
            file_hash: File hash to check (hex string)
            hash_type: Hash algorithm ("sha1", "md5", "sha256")

        Returns:
            True if hash is in NSRL (known-good), False if unknown

        Note:
            SHA-256 lookups require conversion to SHA-1/MD5 (not currently supported).
            If you have SHA-256 only, you must rehash the file with SHA-1 or MD5.
        """
        if not self.loaded:
            self.load()

        file_hash = file_hash.strip().lower()

        if hash_type == "sha1":
            return file_hash in self.sha1_hashes
        elif hash_type == "md5":
            return file_hash in self.md5_hashes
        elif hash_type == "sha256":
            # NSRL doesn't include SHA-256 in most datasets
            # Caller must provide SHA-1 or MD5 for lookup
            logger.warning(
                "SHA-256 lookups not supported. "
                "NSRL uses SHA-1/MD5. Rehash file or provide SHA-1/MD5."
            )
            return False
        else:
            raise ValueError(f"Unsupported hash type: {hash_type}")

    def filter_files(
        self, files: list[tuple[str, str]], hash_type: str = "sha1"
    ) -> tuple[list[tuple[str, str]], list[tuple[str, str]]]:
        """Filter file list into known-good and unknown.

        Args:
            files: List of (file_path, hash) tuples
            hash_type: Hash algorithm used ("sha1", "md5")

        Returns:
            Tuple of (known_good, unknown) file lists

        Example:
            files = [
                ("/carved/file1.exe", "abc123..."),
                ("/carved/file2.dll", "def456..."),
            ]
            known_good, unknown = filter.filter_files(files, hash_type="sha1")
        """
        if not self.loaded:
            self.load()

        known_good = []
        unknown = []

        for file_path, file_hash in files:
            if self.is_known_good(file_hash, hash_type):
                known_good.append((file_path, file_hash))
            else:
                unknown.append((file_path, file_hash))

        logger.info(
            f"NSRL filtering: {len(files)} total, "
            f"{len(known_good)} known-good, "
            f"{len(unknown)} unknown"
        )

        return known_good, unknown

    def get_stats(self) -> dict[str, int]:
        """Get NSRL database statistics.

        Returns:
            Dictionary with loaded status and hash counts
        """
        return {
            "loaded": self.loaded,
            "sha1_count": len(self.sha1_hashes),
            "md5_count": len(self.md5_hashes),
        }


def find_nsrl_database() -> Path | None:
    """Find NSRL database in standard locations.

    Searches:
    1. ~/.sift_find_evil/nsrl/NSRLFile.txt
    2. ./nsrl/NSRLFile.txt
    3. /cases/nsrl/NSRLFile.txt

    Returns:
        Path to NSRLFile.txt if found, None otherwise
    """
    search_paths = [
        Path.home() / ".sift_find_evil" / "nsrl" / "NSRLFile.txt",
        Path.cwd() / "nsrl" / "NSRLFile.txt",
        Path("/cases") / "nsrl" / "NSRLFile.txt",
    ]

    for path in search_paths:
        if path.exists():
            logger.info(f"Found NSRL database: {path}")
            return path

    logger.warning("NSRL database not found in standard locations")
    return None
