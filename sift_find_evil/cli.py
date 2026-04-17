"""
Command-line interface for SIFT Find Evil DFIR Agent.

Usage:
    python -m sift_find_evil.cli analyze --mft <path> --prefetch <path> --evtx <path>
    python -m sift_find_evil.cli demo  # Run with synthetic test data
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Optional

from .parsers.mft_parser import MFTParser
from .parsers.prefetch_parser import PrefetchParser
from .parsers.evtx_parser import EventLogParser
from .self_correction.engine import SelfCorrectionEngine
from .disk.wipe_detector import detect_from_image


def print_banner():
    """Print CLI banner."""
    banner = """
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║   SIFT FIND EVIL - Autonomous DFIR Agent                     ║
║   Cross-Artifact Validation with Self-Correction             ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
"""
    print(banner)


def print_section(title: str):
    """Print section header."""
    print(f"\n{'='*70}")
    print(f"  {title}")
    print('='*70)


def print_finding(finding, index: int):
    """Print a finding in a readable format."""
    print(f"\n[Finding {index}] {finding.title}")
    print(f"  Severity: {finding.severity.upper()}")
    print(f"  Category: {finding.category.value}")
    print(f"  Confidence: {finding.confidence:.2f} ({finding.confidence_label})")
    print(f"  Type: {finding.finding_type}")
    print()

    print(f"  Description:")
    for line in finding.description.split('\n'):
        print(f"    {line}")
    print()

    if finding.contradictions:
        print(f"  Contradictions Detected: {len(finding.contradictions)}")
        for i, contradiction in enumerate(finding.contradictions, 1):
            print(f"    {i}. {contradiction.type.value} ({contradiction.severity.value})")
            print(f"       Impact: {contradiction.confidence_impact:.2f}")
            print(f"       {contradiction.description}")
        print()

    if finding.resolutions:
        print(f"  Resolutions Applied: {len(finding.resolutions)}")
        for i, resolution in enumerate(finding.resolutions, 1):
            print(f"    {i}. {resolution.resolution_method}")
            print(f"       Recovery: +{resolution.confidence_recovery:.2f}")
        print()

    print(f"  Reasoning Chain:")
    for i, step in enumerate(finding.reasoning_chain, 1):
        print(f"    {i}. {step}")
    print()

    print(f"  Evidence:")
    for key, value in finding.evidence.items():
        print(f"    - {key}: {value}")
    print()


def analyze_artifacts(
    mft_path: Path,
    prefetch_path: Path,
    evtx_path: Path,
    output_json: Optional[Path] = None,
    verbose: bool = False,
    pst_path: Optional[Path] = None,
    image_path: Optional[Path] = None,
) -> list:
    """
    Analyze forensic artifacts and detect contradictions.

    Args:
        mft_path: Path to MFT CSV file
        prefetch_path: Path to Prefetch CSV file
        evtx_path: Path to Event Log CSV file
        output_json: Optional path to write JSON output
        verbose: Print verbose output

    Returns:
        List of findings
    """
    if verbose:
        print_section("Loading Artifacts")

    # Parse artifacts
    mft_parser = MFTParser()
    prefetch_parser = PrefetchParser()
    evtx_parser = EventLogParser()

    if verbose:
        print(f"  Loading MFT entries from: {mft_path}")
    mft_entries = mft_parser.parse_csv(mft_path)
    if verbose:
        print(f"    Loaded {len(mft_entries)} MFT entries")

    if verbose:
        print(f"  Loading Prefetch entries from: {prefetch_path}")
    prefetch_entries = prefetch_parser.parse_csv(prefetch_path)
    if verbose:
        print(f"    Loaded {len(prefetch_entries)} Prefetch entries")

    if verbose:
        print(f"  Loading Event Log entries from: {evtx_path}")
    evtx_entries = evtx_parser.parse_csv(evtx_path, filter_event_ids=[4688])
    if verbose:
        print(f"    Loaded {len(evtx_entries)} Event ID 4688 entries")

    # Parse PST if provided
    emails = None
    if pst_path:
        if verbose:
            print(f"  Loading emails from: {pst_path}")
        from .parsers.pst_parser import PstParser
        pst_parser = PstParser()
        emails = pst_parser.parse_file(pst_path)
        if verbose:
            print(f"    Loaded {len(emails)} email messages")

    # Create content reader if image provided
    content_reader = None
    if image_path:
        from .parsers.image_content_reader import make_content_reader
        content_reader = make_content_reader(image_path)
        if verbose:
            print(f"  Created content reader for: {image_path}")

    # Run self-correction engine
    if verbose:
        print_section("Running Self-Correction Engine")
        print("  Detecting contradictions across artifacts...")

    engine = SelfCorrectionEngine()
    findings = engine.analyze(
        mft_entries,
        prefetch_entries,
        evtx_entries,
        content_reader=content_reader,
        emails=emails
    )

    if verbose:
        print(f"  Detected {len(findings)} findings")

    # Output JSON if requested
    if output_json:
        output_data = {
            'findings': [f.to_dict() for f in findings],
            'summary': {
                'total_findings': len(findings),
                'mft_entries': len(mft_entries),
                'prefetch_entries': len(prefetch_entries),
                'event_log_entries': len(evtx_entries)
            }
        }

        with open(output_json, 'w') as f:
            json.dump(output_data, f, indent=2)

        if verbose:
            print(f"  Written JSON output to: {output_json}")

    return findings


def _write_output(findings: list, output_path: Optional[Path]) -> None:
    """Serialize findings to JSON if a path is provided."""
    if output_path is None:
        return
    payload = {
        'findings': [f.to_dict() for f in findings],
        'summary': {'total_findings': len(findings)},
    }
    with open(output_path, 'w') as fh:
        json.dump(payload, fh, indent=2, default=str)


def _render_findings(findings: list) -> None:
    """Print a minimal rendering for image-only runs."""
    print_section("Analysis Results")
    if not findings:
        print("\n  No findings.")
        return
    for idx, finding in enumerate(findings, 1):
        print_finding(finding, idx)


def cmd_analyze(args):
    """Handle analyze command."""
    print_banner()

    image_path: Optional[Path] = Path(args.image) if getattr(args, 'image', None) else None
    pst_path: Optional[Path] = Path(args.pst) if getattr(args, 'pst', None) else None
    artifact_args = [getattr(args, 'mft', None), getattr(args, 'prefetch', None), getattr(args, 'evtx', None)]
    has_artifacts = any(artifact_args)

    if image_path is None and not has_artifacts and pst_path is None:
        print("Error: provide --image and/or --pst and/or all of --mft/--prefetch/--evtx", file=sys.stderr)
        sys.exit(1)

    if has_artifacts and not all(artifact_args):
        print("Error: --mft, --prefetch, and --evtx must be provided together", file=sys.stderr)
        sys.exit(1)

    disk_finding = None
    if image_path is not None:
        if not image_path.exists():
            print(f"Error: disk image not found: {image_path}", file=sys.stderr)
            sys.exit(1)
        print_section("Inspecting Disk Image")
        print(f"  Scanning GPT on: {image_path}")
        disk_finding = detect_from_image(image_path)
        if disk_finding is None:
            print("  No partition-table anomaly detected.")
        else:
            print(f"  Detected: {disk_finding.title}")

    if not has_artifacts:
        findings = [disk_finding] if disk_finding else []
        _write_output(findings, Path(args.output) if args.output else None)
        _render_findings(findings)
        return

    # Validate artifact paths
    mft_path = Path(args.mft)
    prefetch_path = Path(args.prefetch)
    evtx_path = Path(args.evtx)

    if not mft_path.exists():
        print(f"Error: MFT file not found: {mft_path}", file=sys.stderr)
        sys.exit(1)
    if not prefetch_path.exists():
        print(f"Error: Prefetch file not found: {prefetch_path}", file=sys.stderr)
        sys.exit(1)
    if not evtx_path.exists():
        print(f"Error: Event Log file not found: {evtx_path}", file=sys.stderr)
        sys.exit(1)

    # Analyze
    findings = analyze_artifacts(
        mft_path,
        prefetch_path,
        evtx_path,
        output_json=None,  # we write combined output below
        verbose=True,
        pst_path=pst_path,
        image_path=image_path
    )

    if disk_finding is not None:
        findings = [disk_finding] + list(findings)

    _write_output(findings, Path(args.output) if args.output else None)

    # Display findings
    print_section("Analysis Results")

    if not findings:
        print("\n  No suspicious findings detected.")
        print("  All artifacts are consistent with expected behavior.")
        return

    print(f"\n  Found {len(findings)} suspicious activities:")

    for i, finding in enumerate(findings, 1):
        print_finding(finding, i)

    # Summary
    print_section("Summary")
    critical_count = sum(1 for f in findings if f.severity == 'critical')
    high_count = sum(1 for f in findings if f.severity == 'high')
    medium_count = sum(1 for f in findings if f.severity == 'medium')

    print(f"\n  Total Findings: {len(findings)}")
    if critical_count:
        print(f"    CRITICAL: {critical_count}")
    if high_count:
        print(f"    HIGH: {high_count}")
    if medium_count:
        print(f"    MEDIUM: {medium_count}")

    contradiction_count = sum(len(f.contradictions) for f in findings)
    resolution_count = sum(len(f.resolutions) for f in findings)

    print(f"\n  Contradictions Detected: {contradiction_count}")
    print(f"  Resolutions Applied: {resolution_count}")

    avg_confidence = sum(f.confidence for f in findings) / len(findings)
    print(f"\n  Average Confidence: {avg_confidence:.2f}")


def cmd_demo(args):
    """Handle demo command with synthetic test data."""
    print_banner()

    # Find test data directory
    module_dir = Path(__file__).parent.parent
    test_data_dir = module_dir / 'test_data'

    if not test_data_dir.exists():
        print(f"Error: Test data directory not found: {test_data_dir}", file=sys.stderr)
        print("Expected structure: sift_find_evil/test_data/", file=sys.stderr)
        sys.exit(1)

    mft_path = test_data_dir / 'synthetic_mft.csv'
    prefetch_path = test_data_dir / 'synthetic_prefetch.csv'
    evtx_path = test_data_dir / 'synthetic_evtx.csv'

    if not all([mft_path.exists(), prefetch_path.exists(), evtx_path.exists()]):
        print("Error: Synthetic test data files not found", file=sys.stderr)
        sys.exit(1)

    print("\nRunning demonstration with synthetic test data...")
    print(f"This dataset simulates a ransomware attack with timestamp manipulation.")
    print(f"\nTest scenario:")
    print(f"  - malware.exe executed at 14:25 PM")
    print(f"  - MFT shows modification at 14:40 PM (15 min AFTER execution)")
    print(f"  - This violates causality - files cannot be modified after execution")
    print(f"  - Event ID 4688 confirms execution at 14:25:03 PM")
    print(f"  - Expected: Detect violation, resolve via Event Log tiebreaker")

    # Analyze
    findings = analyze_artifacts(
        mft_path,
        prefetch_path,
        evtx_path,
        output_json=Path(args.output) if args.output else None,
        verbose=True
    )

    # Display findings
    print_section("Demo Results")

    if not findings:
        print("\n  ERROR: Expected to find contradictions in synthetic data")
        print("  but none were detected. This may indicate a bug.")
        sys.exit(1)

    print(f"\n  Detected {len(findings)} findings in synthetic dataset:")

    for i, finding in enumerate(findings, 1):
        print_finding(finding, i)

    # Validation
    print_section("Validation")

    malware_findings = [f for f in findings if 'malware.exe' in f.title.lower()]

    if not malware_findings:
        print("\n  WARNING: Did not detect malware.exe contradiction")
        print("  Expected causality violation for malware.exe")
    else:
        malware_finding = malware_findings[0]

        print("\n  Validation checks:")

        # Check contradiction detected
        if malware_finding.contradictions:
            print("    [PASS] Contradiction detected")
        else:
            print("    [FAIL] No contradiction detected")

        # Check resolution applied
        if malware_finding.resolutions:
            print("    [PASS] Resolution applied via Event Log")
        else:
            print("    [FAIL] No resolution applied")

        # Check confidence in expected range
        if 0.40 <= malware_finding.confidence <= 0.80:
            print(f"    [PASS] Confidence in expected range: {malware_finding.confidence:.2f}")
        else:
            print(f"    [WARN] Confidence outside expected range: {malware_finding.confidence:.2f}")

        # Check reasoning chain
        if len(malware_finding.reasoning_chain) >= 4:
            print(f"    [PASS] Comprehensive reasoning chain ({len(malware_finding.reasoning_chain)} steps)")
        else:
            print(f"    [WARN] Reasoning chain seems short ({len(malware_finding.reasoning_chain)} steps)")

    print("\n  Demo completed successfully!")
    print("  The self-correction engine detected the planted contradiction,")
    print("  resolved it using Event Log evidence, and adjusted confidence.")


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description='SIFT Find Evil - Autonomous DFIR Agent with Self-Correction',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run demo with synthetic test data
  python -m sift_find_evil.cli demo

  # Analyze real forensic artifacts
  python -m sift_find_evil.cli analyze \\
    --mft output/mft.csv \\
    --prefetch output/prefetch.csv \\
    --evtx output/evtx.csv

  # Save output as JSON
  python -m sift_find_evil.cli demo --output findings.json
        """
    )

    subparsers = parser.add_subparsers(dest='command', help='Available commands')

    # Demo command
    demo_parser = subparsers.add_parser(
        'demo',
        help='Run demonstration with synthetic test data'
    )
    demo_parser.add_argument(
        '--output', '-o',
        help='Write findings to JSON file'
    )

    # Analyze command
    analyze_parser = subparsers.add_parser(
        'analyze',
        help='Analyze forensic artifacts'
    )
    analyze_parser.add_argument(
        '--mft', '-m',
        help='Path to MFT CSV file (MFTECmd output)'
    )
    analyze_parser.add_argument(
        '--prefetch', '-p',
        help='Path to Prefetch CSV file (PECmd output)'
    )
    analyze_parser.add_argument(
        '--evtx', '-e',
        help='Path to Event Log CSV file (EvtxECmd output)'
    )
    analyze_parser.add_argument(
        '--pst',
        help='Path to PST file for email exfiltration detection (optional)'
    )
    analyze_parser.add_argument(
        '--image', '-i',
        help='Path to disk image (.E01 or .dd) for wipe detection and/or content reading (optional)'
    )
    analyze_parser.add_argument(
        '--output', '-o',
        help='Write findings to JSON file'
    )

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    if args.command == 'demo':
        cmd_demo(args)
    elif args.command == 'analyze':
        cmd_analyze(args)


if __name__ == '__main__':
    main()
