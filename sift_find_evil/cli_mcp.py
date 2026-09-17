"""CLI extension for MCP-based evidence processing.

Usage:
    python -m sift_find_evil.cli_mcp analyze-live \
        --case-id INC-2026-001 \
        --mft-file /evidence/$MFT \
        --prefetch-dir /evidence/Prefetch \
        --evtx-file /evidence/Security.evtx
"""

import argparse
import os
import sys
from pathlib import Path

from .mcp.example_integration import MCPDetectionPipeline
from .self_correction.engine import SelfCorrectionEngine


def _derive_evidence_root(args) -> Path:
    """Resolve the evidence root ToolGuard contains every tool call within.

    A ``--windows-mount`` is itself the root. Otherwise the root is the common
    ancestor of whichever individual evidence inputs were supplied, so a scatter
    of ``--mft-file``/``--evtx-file`` paths under one tree still yields a single
    containing directory (SFE-fibx.14). This must run AFTER windows-mount
    auto-detection has populated the individual paths.
    """
    if args.windows_mount:
        return Path(args.windows_mount).resolve()
    inputs = [args.mft_file, args.prefetch_dir, args.evtx_file, args.memory_file]
    paths = [str(Path(p).resolve()) for p in inputs if p]
    # commonpath returns the common ancestor directory for multiple inputs, or
    # the single path itself for one input -- both are valid containment roots
    # (a lone file resolves relative-to itself). No existence check: the root
    # need not exist yet, and an is_dir() fallback would wrongly broaden a
    # not-yet-mounted ancestor up to its parent.
    root = Path(os.path.commonpath(paths))
    # Reject the degenerate case where inputs from different trees share only the
    # filesystem root: containing to "/" makes input path-containment a no-op, so
    # the guard would accept any path on the box. This is reachable from the CLI
    # (e.g. --mft-file /home/.../x --evtx-file /tmp/y), so fail loudly and make
    # the operator co-locate evidence or pass --windows-mount. A shallow but
    # non-root common dir (e.g. /evidence) is operator-scoped and allowed.
    if root == Path(root.anchor):
        raise ValueError(
            "Evidence inputs share no common directory (the derived root is the "
            "filesystem root). ToolGuard containment would be a no-op. Place all "
            "inputs under one case directory, or pass --windows-mount."
        )
    return root


def cmd_analyze_live(args):
    """Analyze evidence using live forensic tools via MCP.

    This command executes forensic tools (MFTECmd, PECmd, EvtxECmd, Volatility)
    directly on evidence files via MCP, then runs the detection engine.
    """
    # Auto-detect artifacts from mounted Windows filesystem
    if args.windows_mount:
        mount_path = Path(args.windows_mount)

        # Auto-detect MFT
        if not args.mft_file:
            mft_path = mount_path / "$MFT"
            if mft_path.exists():
                args.mft_file = str(mft_path)

        # Auto-detect Prefetch directory
        if not args.prefetch_dir:
            prefetch_path = mount_path / "Windows" / "Prefetch"
            if prefetch_path.exists() and prefetch_path.is_dir():
                args.prefetch_dir = str(prefetch_path)

        # Auto-detect Event Logs (Security.evtx)
        if not args.evtx_file:
            evtx_paths = [
                mount_path
                / "Windows"
                / "System32"
                / "winevt"
                / "Logs"
                / "Security.evtx",
                mount_path / "Windows" / "System32" / "winevt" / "Logs" / "System.evtx",
            ]
            for evtx_path in evtx_paths:
                if evtx_path.exists():
                    args.evtx_file = str(evtx_path)
                    break

    print("\n" + "=" * 70)
    print("  MCP Live Analysis")
    print("=" * 70)
    print(f"\nCase ID: {args.case_id}")
    print("Evidence:")
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
    evidence_root = _derive_evidence_root(args)
    print(f"  Evidence root (ToolGuard containment): {evidence_root}")
    pipeline = MCPDetectionPipeline(
        case_id=args.case_id,
        evidence_root=evidence_root,
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
            try:
                prefetch_entries = pipeline.analyze_prefetch(
                    Path(args.prefetch_dir), output_dir
                )
                print(f"    Parsed {len(prefetch_entries)} Prefetch entries")
            except RuntimeError as e:
                # Handle known Windows-only error gracefully.
                #
                # The platform gate (SFE-ybki) is what actually raises here now:
                # before it existed, PECmd exited 0 while refusing to work, so
                # nothing raised and this handler was dead code. Match its message
                # case-insensitively -- the gate names the tool by its lowercase
                # logical key ("pecmd"), which the case-sensitive "PECmd" test
                # below would miss. The older substrings are kept for the case
                # where PECmd itself does surface its own refusal text.
                message = str(e)
                if (
                    "not supported on this platform" in message.lower()
                    or "Non-Windows platforms" in message
                    or "PECmd" in message
                ):
                    print(f"    ⚠️  PECmd skipped (requires Windows): {str(e)[:100]}")
                    print("    Continuing analysis without Prefetch data...")
                else:
                    # Unknown error - respect strict mode
                    if args.strict_mode:
                        raise  # Re-raise in strict mode
                    else:
                        print(f"    ⚠️  PECmd failed: {e}")
                        print("    Continuing analysis without Prefetch data...")

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

    print("\nNext steps:")
    print(f"  1. Review findings: {findings_file}")
    print("  2. Approve findings: python -m sift_find_evil.cli approve ...")
    print("  3. Generate report: python -m sift_find_evil.cli report ...")

    return 0


def main():
    """MCP CLI entry point."""
    parser = argparse.ArgumentParser(description="SIFT Find Evil - MCP Live Analysis")

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
        "--windows-mount",
        help="Path to mounted Windows filesystem (auto-detects MFT, Prefetch, Event Logs)",
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

    parser.add_argument(
        "--strict-mode",
        action="store_true",
        help="Stop on first unknown error (recommended for court evidence)",
    )

    args = parser.parse_args()

    # Validate at least one evidence source
    if not any(
        [
            args.windows_mount,
            args.mft_file,
            args.prefetch_dir,
            args.evtx_file,
            args.memory_file,
        ]
    ):
        print(
            "ERROR: At least one evidence source required (--windows-mount, --mft-file, --prefetch-dir, --evtx-file, or --memory-file)",
            file=sys.stderr,
        )
        return 1

    if args.command == "analyze-live":
        return cmd_analyze_live(args)

    return 0


if __name__ == "__main__":
    sys.exit(main())
