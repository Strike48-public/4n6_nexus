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

Backends:
- set (default): exact match, ~2-3 GB RAM for Modern RDS, ~8-10 GB for Full RDS
- bloom (opt-in): probabilistic match via rbloom, ~400 MB for 200M hashes at p=0.001
  * Bloom filters have no false negatives (a hash in NSRL is always flagged)
  * Bloom filters have tunable false positives (an unknown hash can rarely be
    flagged as known-good). At the default p=0.001 this means one false match
    per ~1000 unknown files, acceptable for triage noise reduction; it shrinks
    the investigation surface without discarding evidence.

Performance:
- set lookup: <1 microsecond per hash, O(1)
- bloom lookup: ~1-2 microseconds per hash, O(k) where k = hash count (~10)
- First load: 30-60 seconds for Modern RDS (parsing CSV, building index)
"""

from __future__ import annotations

import csv
import logging
from pathlib import Path
from typing import Any, Protocol

logger = logging.getLogger(__name__)


class HashBackend(Protocol):
    """Minimal contract both NSRL backends (set and bloom) satisfy."""

    def add(self, item: str, /) -> None: ...
    def __contains__(self, item: object, /) -> bool: ...

# Bloom filter defaults tuned for NSRL Full RDS (~220M hashes).
# At p=0.001 the filter fits in ~400 MB and false-positive rate stays
# below one match per thousand unknown files.
DEFAULT_BLOOM_EXPECTED_ITEMS = 220_000_000
DEFAULT_BLOOM_FP_RATE = 0.001


def _make_bloom(expected_items: int, false_positive_rate: float) -> Any:
    """Construct an rbloom Bloom filter, deferring the import.

    Args:
        expected_items: Upper bound on the number of items to insert.
        false_positive_rate: Target false-positive probability (0 < p < 1).

    Returns:
        A configured `rbloom.Bloom` instance.

    Raises:
        ImportError: If `rbloom` is not installed. Install with:
            pip install rbloom
    """
    try:
        from rbloom import Bloom
    except ImportError as exc:
        raise ImportError(
            "rbloom is required for bloom-backed NSRL filtering. "
            "Install with: pip install rbloom"
        ) from exc
    return Bloom(expected_items, false_positive_rate)


class NSRLFilter:
    """NSRL hash filter for known-good file identification.

    Loads NSRL RDS database and provides fast hash lookup for filtering
    legitimate system files during carved file analysis.

    Two backends are available:

    * set (default): exact match, ~2-3 GB RAM for Modern RDS.
    * bloom: probabilistic match via `rbloom`, ~400 MB RAM for 200M hashes
      at p=0.001. Chosen via ``use_bloom=True`` in the constructor.

    Attributes:
        nsrl_path: Path to NSRLFile.txt
        use_bloom: Whether the bloom-filter backend is active
        loaded: Whether database is loaded in memory
    """

    def __init__(
        self,
        nsrl_path: str | Path,
        *,
        use_bloom: bool = False,
        expected_items: int = DEFAULT_BLOOM_EXPECTED_ITEMS,
        false_positive_rate: float = DEFAULT_BLOOM_FP_RATE,
    ):
        """Initialize NSRL filter.

        Args:
            nsrl_path: Path to NSRLFile.txt from NSRL RDS
            use_bloom: If True, use a bloom filter backend (memory-efficient
                but with tunable false positives). If False (default), use an
                exact Python set.
            expected_items: Bloom-only. Upper bound on hash count; drives the
                bit-array size. Defaults to 220M (Full RDS).
            false_positive_rate: Bloom-only. Target false-positive probability.
                Defaults to 0.001 (one in a thousand unknown files).

        Raises:
            FileNotFoundError: If NSRLFile.txt not found.
            ImportError: If ``use_bloom=True`` and rbloom is not installed.
        """
        self.nsrl_path = Path(nsrl_path)
        if not self.nsrl_path.exists():
            raise FileNotFoundError(
                f"NSRL database not found: {self.nsrl_path}\n"
                f"Run: ./scripts/download-nsrl.sh modern"
            )

        self.use_bloom = use_bloom
        self._expected_items = expected_items
        self._false_positive_rate = false_positive_rate

        self.sha1_hashes: HashBackend
        self.md5_hashes: HashBackend
        if use_bloom:
            self.sha1_hashes = _make_bloom(expected_items, false_positive_rate)
            self.md5_hashes = _make_bloom(expected_items, false_positive_rate)
        else:
            self.sha1_hashes = set()
            self.md5_hashes = set()

        self.loaded = False

    def load(self) -> None:
        """Load NSRL database into memory.

        Parses NSRLFile.txt and populates the active backend (set or bloom).
        One-time operation (30-60 seconds for Modern RDS).

        CSV format:
        "SHA-1","MD5","CRC32","FileName","FileSize","ProductCode","OpSystemCode","SpecialCode"

        Raises:
            ValueError: If NSRLFile.txt format is invalid
        """
        if self.loaded:
            logger.debug("NSRL database already loaded")
            return

        backend = "bloom" if self.use_bloom else "set"
        logger.info(f"Loading NSRL database ({backend} backend): {self.nsrl_path}")
        logger.info("This may take 30-60 seconds...")

        try:
            with open(self.nsrl_path, "r", encoding="utf-8", errors="ignore") as f:
                reader = csv.DictReader(f)

                expected_fields = {"SHA-1", "MD5"}
                if not expected_fields.issubset(reader.fieldnames or []):
                    raise ValueError(
                        f"Invalid NSRL format. Expected fields: {expected_fields}, "
                        f"found: {reader.fieldnames}"
                    )

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
            sha1_count, md5_count = self._hash_counts()
            logger.info(
                f"NSRL database loaded ({backend}): {sha1_count:,} SHA-1 hashes, "
                f"{md5_count:,} MD5 hashes"
            )

        except Exception as e:
            logger.error(f"Failed to load NSRL database: {e}")
            raise

    def _hash_counts(self) -> tuple[int, int]:
        """Return (sha1_count, md5_count) for whichever backend is active.

        For bloom filters this is an approximation (``approx_items``); for
        sets this is exact (``len``).
        """
        if self.use_bloom:
            return (
                int(round(self.sha1_hashes.approx_items)),
                int(round(self.md5_hashes.approx_items)),
            )
        return len(self.sha1_hashes), len(self.md5_hashes)

    def is_known_good(self, file_hash: str, hash_type: str = "sha1") -> bool:
        """Check if file hash is in NSRL database.

        Args:
            file_hash: File hash to check (hex string)
            hash_type: Hash algorithm ("sha1", "md5", "sha256")

        Returns:
            True if hash is in NSRL (known-good), False if unknown. When the
            bloom backend is active, True may be a rare false positive bounded
            by ``false_positive_rate``; False is always authoritative.

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
            Tuple of (known_good, unknown) file lists.

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

    def get_stats(self) -> dict[str, Any]:
        """Get NSRL database statistics.

        Returns:
            Dictionary with loaded status, hash counts, and backend metadata.
            For bloom backends, ``sha1_count`` / ``md5_count`` are estimates.
        """
        sha1_count, md5_count = self._hash_counts()
        stats: dict[str, Any] = {
            "loaded": self.loaded,
            "sha1_count": sha1_count,
            "md5_count": md5_count,
            "backend": "bloom" if self.use_bloom else "set",
        }
        if self.use_bloom:
            stats["expected_items"] = self._expected_items
            stats["false_positive_rate"] = self._false_positive_rate
            stats["size_bytes"] = self.sha1_hashes.size_in_bits // 8 + (
                self.md5_hashes.size_in_bits // 8
            )
        return stats


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
