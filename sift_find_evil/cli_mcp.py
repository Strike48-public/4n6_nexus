"""CLI extension for MCP-based evidence processing.

Usage:
    python -m sift_find_evil.cli_mcp analyze-live \
        --case-id INC-2026-001 \
        --mft-file /evidence/$MFT \
        --prefetch-dir /evidence/Prefetch \
        --evtx-file /evidence/Security.evtx
"""

import argparse
import sys
from pathlib import Path

from .mcp.example_integration import MCPDetectionPipeline
from .self_correction.engine import SelfCorrectionEngine


def cmd_analyze_live(args):
    """Analyze evidence using live forensic tools via MCP.

    This command executes forensic tools (MFTECmd, PECmd, EvtxECmd, Volatility)
    directly on evidence files via MCP, then runs the detection engine.
    """
    print("\n" + "=" * 70)
    print("  MCP Live Analysis")
    print("=" * 70)
    print(f"\nCase ID: {args.case_id}")
    print(f"Evidence:")
    if args.mft_file:
        print(f"  - MFT: {args.mft_file}")
    if args.prefetch_dir:
        print(f"  - Prefetch: {args.prefetch_dir}")
    if args.evtx_file:
        print(f"  - Event Logs: {args.evtx_file}")
    if args.memory_file:
        print(f"  - Memory: {args.memory_file}")
    print()

    # Initialize MCP pipeline
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    audit_log = output_dir / "audit.jsonl"
    pipeline = MCPDetectionPipeline(
        case_id=args.case_id,
        audit_log_path=audit_log,
        timeout_seconds=args.timeout,
    )

    print("[1/3] Executing forensic tools via MCP...")
    print(f"  Output directory: {output_dir}")
    print(f"  Audit log: {audit_log}")
    print(f"  Timeout: {args.timeout}s")
    print()

    # Run tools via MCP
    mft_entries = []
    prefetch_entries = []
    evtx_entries = []
    memory_results = {}

    try:
        if args.mft_file:
            print(f"  Running MFTECmd on {args.mft_file}...")
            mft_entries = pipeline.analyze_mft(Path(args.mft_file), output_dir)
            print(f"    Parsed {len(mft_entries)} MFT entries")

        if args.prefetch_dir:
            print(f"  Running PECmd on {args.prefetch_dir}...")
            prefetch_entries = pipeline.analyze_prefetch(
                Path(args.prefetch_dir), output_dir
            )
            print(f"    Parsed {len(prefetch_entries)} Prefetch entries")

        if args.evtx_file:
            print(f"  Running EvtxECmd on {args.evtx_file}...")
            evtx_entries = pipeline.analyze_evtx(Path(args.evtx_file), output_dir)
            print(f"    Parsed {len(evtx_entries)} Event Log entries")

        if args.memory_file:
            print(f"  Running Volatility 3 on {args.memory_file}...")
            memory_results = pipeline.analyze_memory(Path(args.memory_file), output_dir)
            plugins_run = len([k for k in memory_results if not k.endswith("_error")])
            print(f"    Ran {plugins_run} Volatility plugins")

    except Exception as e:
        print(f"\n[ERROR] Tool execution failed: {e}", file=sys.stderr)
        return 1

    print("\n[2/3] Running self-correction engine...")

    # Run detection engine
    engine = SelfCorrectionEngine()
    findings = engine.analyze(
        mft_entries=mft_entries,
        prefetch_entries=prefetch_entries,
        event_log_entries=evtx_entries,
    )

    print(f"  Detected {len(findings)} findings")

    print("\n[3/3] Generating output...")

    # Write findings to JSON
    findings_file = output_dir / "findings.json"
    findings_data = [f.to_dict() for f in findings]

    with open(findings_file, "w") as f:
        import json

        json.dump(findings_data, f, indent=2)

    print(f"  Findings written to: {findings_file}")
    print(f"  Audit log written to: {audit_log}")

    # Print summary
    print("\n" + "=" * 70)
    print("  Analysis Complete")
    print("=" * 70)
    print(f"\nTotal findings: {len(findings)}")

    severity_counts = {}
    for finding in findings:
        severity = finding.severity
        severity_counts[severity] = severity_counts.get(severity, 0) + 1

    if severity_counts:
        print("\nSeverity breakdown:")
        for severity in ["critical", "high", "medium", "low"]:
            count = severity_counts.get(severity, 0)
            if count > 0:
                print(f"  {severity.upper()}: {count}")

    print(f"\nNext steps:")
    print(f"  1. Review findings: {findings_file}")
    print(f"  2. Approve findings: python -m sift_find_evil.cli approve ...")
    print(f"  3. Generate report: python -m sift_find_evil.cli report ...")

    return 0


def main():
    """MCP CLI entry point."""
    parser = argparse.ArgumentParser(
        description="SIFT Find Evil - MCP Live Analysis"
    )

    parser.add_argument(
        "command",
        choices=["analyze-live"],
        help="Command to execute",
    )

    parser.add_argument(
        "--case-id",
        required=True,
        help="Case identifier (e.g., INC-2026-001)",
    )

    parser.add_argument(
        "--mft-file",
        help="Path to $MFT file",
    )

    parser.add_argument(
        "--prefetch-dir",
        help="Path to Prefetch directory",
    )

    parser.add_argument(
        "--evtx-file",
        help="Path to .evtx file",
    )

    parser.add_argument(
        "--memory-file",
        help="Path to memory dump",
    )

    parser.add_argument(
        "--output-dir",
        default="./analysis",
        help="Output directory for tool outputs and findings (default: ./analysis)",
    )

    parser.add_argument(
        "--timeout",
        type=int,
        default=300,
        help="Tool timeout in seconds (default: 300)",
    )

    args = parser.parse_args()

    # Validate at least one evidence source
    if not any([args.mft_file, args.prefetch_dir, args.evtx_file, args.memory_file]):
        print(
            "ERROR: At least one evidence source required (--mft-file, --prefetch-dir, --evtx-file, or --memory-file)",
            file=sys.stderr,
        )
        return 1

    if args.command == "analyze-live":
        return cmd_analyze_live(args)

    return 0


if __name__ == "__main__":
    sys.exit(main())
