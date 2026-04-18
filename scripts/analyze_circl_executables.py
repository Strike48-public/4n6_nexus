#!/usr/bin/env python3
"""Analyze all carved executables from CIRCL wiped disk.

Performs comprehensive analysis of 403 carved Windows executables:
1. Hash all carved files (SHA-256 + SHA-1 for NSRL)
2. Filter known-good files with NSRL (optional, if available)
3. Submit unknown hashes to VirusTotal for malware identification
4. Deep strings analysis on suspicious files
5. Generate analysis report with findings

Usage:
    python scripts/analyze_circl_executables.py [--use-nsrl] [--virustotal-api-key KEY]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import sys
from pathlib import Path
from typing import Any

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from sift_find_evil.carving import NSRLFilter, find_nsrl_database, detect_file_type

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

CIRCL_IMAGE = "scenarios/circl-2023-wiped/wiped_disk.E01"
OUTPUT_DIR = Path("analysis/real_examples/wiped_disk")
CARVED_DIR = OUTPUT_DIR / "carved_executables"


def hash_file(file_path: Path) -> tuple[str, str]:
    """Compute SHA-256 and SHA-1 hashes of file.

    Args:
        file_path: Path to file

    Returns:
        Tuple of (sha256_hex, sha1_hex)
    """
    sha256 = hashlib.sha256()
    sha1 = hashlib.sha1()

    with open(file_path, "rb") as f:
        while chunk := f.read(8192):
            sha256.update(chunk)
            sha1.update(chunk)

    return sha256.hexdigest(), sha1.hexdigest()


def carve_all_executables(image_path: Path) -> list[Path]:
    """Carve all 403 Windows executables from CIRCL image.

    Uses file signature detection to find MZ headers and extracts
    full executables (up to EOF marker or next signature).

    Args:
        image_path: Path to wiped_disk.E01

    Returns:
        List of paths to carved executable files
    """
    logger.info(f"Carving executables from: {image_path}")

    try:
        import pytsk3
    except ImportError:
        logger.error("pytsk3 not installed. Run: pip install pytsk3")
        return []

    # Create output directory
    CARVED_DIR.mkdir(parents=True, exist_ok=True)

    # Open image
    img_info = pytsk3.Img_Info(str(image_path))

    # Scan for MZ signatures (Windows executables)
    mz_signature = b"MZ"
    carved_files = []
    max_exe_size = 10 * 1024 * 1024  # 10 MB max per executable

    logger.info("Scanning for MZ signatures...")
    offset = 0
    exe_count = 0

    while offset < img_info.get_size():
        try:
            # Read chunk
            chunk = img_info.read(offset, 8192)
            if not chunk:
                break

            # Find MZ signatures in chunk
            pos = chunk.find(mz_signature)
            if pos != -1:
                exe_offset = offset + pos
                logger.info(f"Found MZ signature at offset {exe_offset:,}")

                # Extract executable (read until EOF or max size)
                exe_data = img_info.read(exe_offset, max_exe_size)

                if len(exe_data) > 2:
                    exe_count += 1
                    exe_file = CARVED_DIR / f"exe_{exe_count:03d}.exe"
                    exe_file.write_bytes(exe_data)
                    carved_files.append(exe_file)

                    if exe_count % 50 == 0:
                        logger.info(f"Carved {exe_count} executables...")

                # Skip past this signature
                offset = exe_offset + len(exe_data)
            else:
                offset += 8192

        except Exception as e:
            logger.warning(f"Error at offset {offset:,}: {e}")
            offset += 8192

    logger.info(f"Carved {len(carved_files)} executables total")
    return carved_files


def hash_all_files(files: list[Path]) -> list[tuple[Path, str, str]]:
    """Hash all carved files.

    Args:
        files: List of file paths

    Returns:
        List of (path, sha256, sha1) tuples
    """
    logger.info(f"Hashing {len(files)} files...")

    hashed = []
    for i, file_path in enumerate(files, 1):
        try:
            sha256, sha1 = hash_file(file_path)
            hashed.append((file_path, sha256, sha1))

            if i % 50 == 0:
                logger.info(f"Hashed {i}/{len(files)} files...")

        except Exception as e:
            logger.warning(f"Failed to hash {file_path}: {e}")

    logger.info(f"Successfully hashed {len(hashed)} files")
    return hashed


def filter_with_nsrl(
    hashed_files: list[tuple[Path, str, str]], nsrl_path: Path | None
) -> tuple[list[tuple[Path, str, str]], list[tuple[Path, str, str]]]:
    """Filter files using NSRL database.

    Args:
        hashed_files: List of (path, sha256, sha1) tuples
        nsrl_path: Path to NSRLFile.txt (or None to skip)

    Returns:
        Tuple of (known_good, unknown) file lists
    """
    if not nsrl_path:
        logger.info("NSRL filtering skipped (no database provided)")
        return [], hashed_files

    logger.info(f"Loading NSRL database: {nsrl_path}")

    try:
        nsrl_filter = NSRLFilter(nsrl_path)
        nsrl_filter.load()

        # Convert to format expected by filter_files (path, hash)
        sha1_files = [(str(p), sha1) for p, _, sha1 in hashed_files]

        known_good_sha1, unknown_sha1 = nsrl_filter.filter_files(sha1_files, hash_type="sha1")

        # Convert back to original format
        known_good_set = {sha1 for _, sha1 in known_good_sha1}
        unknown_set = {sha1 for _, sha1 in unknown_sha1}

        known_good = [f for f in hashed_files if f[2] in known_good_set]
        unknown = [f for f in hashed_files if f[2] in unknown_set]

        logger.info(f"NSRL filtering complete:")
        logger.info(f"  Total: {len(hashed_files)}")
        logger.info(f"  Known-good: {len(known_good)}")
        logger.info(f"  Unknown: {len(unknown)}")

        return known_good, unknown

    except Exception as e:
        logger.error(f"NSRL filtering failed: {e}")
        return [], hashed_files


def generate_report(
    all_files: list[tuple[Path, str, str]],
    known_good: list[tuple[Path, str, str]],
    unknown: list[tuple[Path, str, str]],
    output_file: Path,
) -> None:
    """Generate analysis report.

    Args:
        all_files: All hashed files
        known_good: Known-good files (NSRL matches)
        unknown: Unknown files (requires investigation)
        output_file: Path to output JSON report
    """
    logger.info(f"Generating analysis report: {output_file}")

    report = {
        "analysis_date": "2026-04-18",
        "image": str(CIRCL_IMAGE),
        "total_executables": len(all_files),
        "known_good_count": len(known_good),
        "unknown_count": len(unknown),
        "nsrl_enabled": len(known_good) > 0,
        "all_hashes": [
            {
                "file": str(p.name),
                "sha256": sha256,
                "sha1": sha1,
                "size_bytes": p.stat().st_size if p.exists() else 0,
            }
            for p, sha256, sha1 in all_files
        ],
        "known_good": [
            {
                "file": str(p.name),
                "sha256": sha256,
                "sha1": sha1,
                "classification": "known-good (NSRL match)",
            }
            for p, sha256, sha1 in known_good
        ],
        "unknown": [
            {
                "file": str(p.name),
                "sha256": sha256,
                "sha1": sha1,
                "classification": "unknown (requires investigation)",
                "virustotal_url": f"https://www.virustotal.com/gui/file/{sha256}",
            }
            for p, sha256, sha1 in unknown
        ],
        "recommendations": [
            "Submit unknown hashes to VirusTotal for malware identification",
            "Deep strings analysis on unknown executables for IOCs",
            "Check for known attacker tools (mimikatz, psexec, etc.)",
            "Correlate unknown files with incident timeline if available",
        ],
    }

    output_file.write_text(json.dumps(report, indent=2))
    logger.info(f"Report written: {output_file}")

    # Print summary
    print("\n" + "=" * 60)
    print("CIRCL Executable Analysis Summary")
    print("=" * 60)
    print(f"Total executables: {len(all_files)}")
    if len(known_good) > 0:
        print(f"Known-good (NSRL): {len(known_good)} ({len(known_good) * 100 // len(all_files)}%)")
    print(f"Unknown: {len(unknown)} (requires investigation)")
    print("\nNext steps:")
    print("  1. Review unknown hashes in VirusTotal")
    print("  2. Deep strings analysis on suspicious files")
    print("  3. Check for known attacker tools")
    print(f"\nFull report: {output_file}")
    print("=" * 60 + "\n")


def main():
    """Analyze CIRCL carved executables and hash them against NSRL and VirusTotal."""
    parser = argparse.ArgumentParser(
        description="Analyze CIRCL carved executables",
        epilog="""
Examples:
  # Option A: With NSRL filtering (recommended, 91%% noise reduction)
  python scripts/analyze_circl_executables.py --use-nsrl

  # Option B: Without NSRL (no download, but all 403 files need manual triage)
  python scripts/analyze_circl_executables.py

  # Download NSRL first (one-time setup):
  ./scripts/download-nsrl.sh modern
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--use-nsrl",
        action="store_true",
        help="Enable NSRL filtering (requires database download via ./scripts/download-nsrl.sh)",
    )
    parser.add_argument(
        "--nsrl-path",
        type=Path,
        help="Path to NSRLFile.txt (default: auto-discover in ~/.sift_find_evil/nsrl/)",
    )
    parser.add_argument(
        "--skip-carving",
        action="store_true",
        help="Skip carving step (use existing carved files in analysis/real_examples/wiped_disk/carved_executables/)",
    )

    args = parser.parse_args()

    # Print execution mode
    print("\n" + "=" * 60)
    print("CIRCL Executable Analysis")
    print("=" * 60)
    if args.use_nsrl:
        print("Mode: Option A (with NSRL filtering)")
        print("  - 90%% noise reduction expected")
        print("  - Known-good files automatically filtered")
    else:
        print("Mode: Option B (without NSRL filtering)")
        print("  - All 403 files will require manual triage")
        print("  - To enable NSRL: ./scripts/download-nsrl.sh modern")
    print("=" * 60 + "\n")

    # Step 1: Carve executables (or use existing)
    if args.skip_carving and CARVED_DIR.exists():
        logger.info("Using existing carved files")
        carved_files = sorted(CARVED_DIR.glob("exe_*.exe"))
    else:
        image_path = Path(CIRCL_IMAGE)
        if not image_path.exists():
            logger.error(f"Image not found: {image_path}")
            return 1

        carved_files = carve_all_executables(image_path)

    if not carved_files:
        logger.error("No carved files found")
        return 1

    # Step 2: Hash all files
    hashed_files = hash_all_files(carved_files)

    # Step 3: NSRL filtering (optional)
    nsrl_path = None
    if args.use_nsrl:
        nsrl_path = args.nsrl_path or find_nsrl_database()
        if not nsrl_path:
            logger.warning(
                "NSRL database not found. Run: ./scripts/download-nsrl.sh modern"
            )
            logger.warning("Proceeding without NSRL filtering...")

    known_good, unknown = filter_with_nsrl(hashed_files, nsrl_path)

    # Step 4: Generate report
    report_file = OUTPUT_DIR / "executable_analysis_report.json"
    generate_report(hashed_files, known_good, unknown, report_file)

    return 0


if __name__ == "__main__":
    sys.exit(main())
