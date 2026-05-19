#!/usr/bin/env python3
"""
Diagnostic tool to check if a path can be scanned by the TUI.

Usage:
    python3 diagnose_path.py /path/to/evidence

Checks:
- Path exists and is readable
- Can enumerate files recursively
- Finds forensic artifacts (CSV files, executables, etc.)
- Estimates scan time
"""

import sys
import time
from pathlib import Path
from collections import Counter


def diagnose_path(evidence_path: Path) -> None:
    """Diagnose why a path might not scan properly."""
    print("=" * 70)
    print(f"EVIDENCE PATH DIAGNOSTIC: {evidence_path}")
    print("=" * 70)

    # Check 1: Path exists
    print("\n[1] Path Existence Check")
    if not evidence_path.exists():
        print(f"❌ FAIL: Path does not exist: {evidence_path}")
        return
    print(f"✓ Path exists: {evidence_path}")

    # Check 2: Path type
    print("\n[2] Path Type Check")
    if evidence_path.is_file():
        print(f"ℹ Path is a FILE (will be treated as disk image)")
        print(f"  Size: {evidence_path.stat().st_size / (1024**3):.2f} GB")
        return
    elif evidence_path.is_dir():
        print(f"✓ Path is a DIRECTORY")
    else:
        print(f"❌ FAIL: Path is neither file nor directory")
        return

    # Check 3: Directory listing
    print("\n[3] Directory Listing Check")
    try:
        immediate_children = list(evidence_path.iterdir())
        print(f"✓ Can list directory: {len(immediate_children)} immediate children")

        # Show first 10 items
        print("\n  Top-level contents:")
        for i, child in enumerate(immediate_children[:10], 1):
            type_icon = "📁" if child.is_dir() else "📄"
            print(f"    {i}. {type_icon} {child.name}")

        if len(immediate_children) > 10:
            print(f"    ... and {len(immediate_children) - 10} more items")

    except PermissionError as e:
        print(f"❌ FAIL: Permission denied listing directory: {e}")
        return
    except Exception as e:
        print(f"❌ FAIL: Error listing directory: {e}")
        return

    # Check 4: Recursive scan (with limit for safety)
    print("\n[4] Recursive Scan Check (limited to 10,000 files)")
    try:
        start = time.time()
        all_files = []
        file_count = 0

        for f in evidence_path.rglob("*"):
            if f.is_file():
                all_files.append(f)
                file_count += 1
                if file_count >= 10000:
                    print(f"  ⚠ Stopped at 10,000 files for safety")
                    break

        elapsed = time.time() - start
        print(f"✓ Scanned {len(all_files)} files in {elapsed:.2f}s")

        if len(all_files) == 0:
            print(f"  ⚠ WARNING: No files found in directory tree")
            print(f"  This is unusual - check if the directory is empty or has permission issues")

    except PermissionError as e:
        print(f"❌ FAIL: Permission denied during recursive scan: {e}")
        return
    except Exception as e:
        print(f"❌ FAIL: Error during recursive scan: {e}")
        import traceback
        traceback.print_exc()
        return

    # Check 5: Forensic artifacts
    print("\n[5] Forensic Artifact Detection")

    # CSV files (synthetic fixtures)
    csv_files = [f for f in all_files if f.suffix.lower() == '.csv']
    print(f"  CSV files: {len(csv_files)}")
    if csv_files:
        csv_names = Counter(f.name for f in csv_files)
        for name, count in csv_names.most_common(5):
            print(f"    - {name}: {count}")

    # Executables
    exe_files = [f for f in all_files if f.suffix.lower() in ['.exe', '.dll', '.sys']]
    print(f"  Executables: {len(exe_files)}")

    # Prefetch
    prefetch_files = [f for f in all_files if 'prefetch' in f.name.lower()]
    print(f"  Prefetch files: {len(prefetch_files)}")

    # Memory dumps
    mem_files = [f for f in all_files if f.suffix.lower() in ['.dmp', '.mem', '.raw']]
    print(f"  Memory dumps: {len(mem_files)}")

    # LNK files
    lnk_files = [f for f in all_files if f.suffix.lower() == '.lnk']
    print(f"  LNK files: {len(lnk_files)}")

    # Check 6: File type distribution
    print("\n[6] File Type Distribution (top 15)")
    exts = Counter(f.suffix.lower() for f in all_files)
    for ext, count in exts.most_common(15):
        print(f"  {ext or '(no ext)'}: {count}")

    # Check 7: Recommendations
    print("\n" + "=" * 70)
    print("RECOMMENDATIONS:")
    print("=" * 70)

    if len(all_files) == 0:
        print("❌ No files found - TUI will not find any evidence to analyze")
        print("   Check:")
        print("   - Is this the correct directory?")
        print("   - Does it have subdirectories with files?")
        print("   - Do you have read permissions?")
    elif len(csv_files) > 0:
        print("✓ Found CSV fixtures - Quick/Full/Timeline analysis should work")
    elif len(exe_files) > 0:
        print("✓ Found executables - YARA scanning will work")
    else:
        print("⚠ No forensic artifacts detected")
        print("   This appears to be a regular directory, not forensic evidence")
        print("   The TUI will scan files but may not generate findings")

    if len(all_files) > 10000:
        print(f"\n⚠ Large dataset ({len(all_files)} files)")
        print("   Analysis may take several minutes")
        print("   Consider using Quick Triage mode")

    print("\n✓ Diagnostic complete - path should be scannable by TUI")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 diagnose_path.py /path/to/evidence")
        print("\nExample:")
        print("  python3 diagnose_path.py /media/user/TESLADRIVE")
        print("  python3 diagnose_path.py scenarios/synthetic/02_ransomware")
        sys.exit(1)

    path = Path(sys.argv[1])
    diagnose_path(path)
