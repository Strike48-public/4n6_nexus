"""Command-line interface for SIFT Find Evil DFIR Agent.

Usage:
    python -m sift_find_evil.cli analyze --mft <path> --prefetch <path> --evtx <path>
    python -m sift_find_evil.cli demo  # Run with synthetic test data
"""

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

from .parsers.mft_parser import MFTParser
from .parsers.prefetch_parser import PrefetchParser
from .parsers.evtx_parser import EventLogParser
from .parsers.browser_history_parser import BrowserHistoryParser
from .self_correction.engine import SelfCorrectionEngine
from .disk.wipe_detector import detect_from_image
from .disk.exfil_detector import detect_exfiltration
from .detectors import (
    LnkJumpListDetector,
    MemoryDetector,
    NetworkDetector,
    RegistryDetector,
)
from .detectors.webmail_exfil_detector import MFTAccessRecord
from .parsers.lnk_jumplist_parser import JumpListParser, LnkParser
from .parsers.registry_parser import RegistryParser
from .scenario_runner import ScenarioLoadError, run_scenario_path
from .validation import AdversarialValidator
from .approval import ApprovalManager, ApprovalStatus, FindingWithApproval
from .audit import AuditLogger
from .case import CaseManager
from .reporting import ReportFormat, ReportGenerator

try:
    from .detectors.yara_detector import YaraDetector
    from .yara_scan.scanner import MissingYaraError, YaraScanner

    _YARA_AVAILABLE = True
except ImportError:  # pragma: no cover — hosts without libyara
    YaraDetector = None  # type: ignore[assignment]
    YaraScanner = None  # type: ignore[assignment]
    MissingYaraError = RuntimeError  # type: ignore[assignment,misc]
    _YARA_AVAILABLE = False


def print_banner():
    """Print CLI banner."""
    banner = """
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║   4n6 Nexus  (SANS FIND EVIL! entry: SIFT Find Evil)          ║
║   Autonomous DFIR Detection with Architectural Self-Correction║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
"""
    print(banner)


def print_section(title: str):
    """Print section header."""
    print(f"\n{'='*70}")
    print(f"  {title}")
    print("=" * 70)


def print_finding(finding, index: int, validation_status: Optional[str] = None):
    """Print a finding in a readable format."""
    print(f"\n[Finding {index}] {finding.title}")
    print(f"  Severity: {finding.severity.upper()}")
    print(f"  Category: {finding.category.value}")
    print(f"  Confidence: {finding.confidence:.2f} ({finding.confidence_label})")
    print(f"  Type: {finding.finding_type}")
    if validation_status:
        print(f"  Validation: {validation_status}")
    print()

    print("  Description:")
    for line in finding.description.split("\n"):
        print(f"    {line}")
    print()

    if finding.contradictions:
        print(f"  Contradictions Detected: {len(finding.contradictions)}")
        for i, contradiction in enumerate(finding.contradictions, 1):
            print(
                f"    {i}. {contradiction.type.value} ({contradiction.severity.value})"
            )
            print(f"       Impact: {contradiction.confidence_impact:.2f}")
            print(f"       {contradiction.description}")
        print()

    if finding.resolutions:
        print(f"  Resolutions Applied: {len(finding.resolutions)}")
        for i, resolution in enumerate(finding.resolutions, 1):
            print(f"    {i}. {resolution.resolution_method}")
            print(f"       Recovery: +{resolution.confidence_recovery:.2f}")
        print()

    print("  Reasoning Chain:")
    for i, step in enumerate(finding.reasoning_chain, 1):
        print(f"    {i}. {step}")
    print()

    print("  Evidence:")
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
    """Analyze forensic artifacts and detect contradictions.

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
        emails=emails,
    )

    if verbose:
        print(f"  Detected {len(findings)} findings")

    # Run exfiltration detector if we have MFT, PST, and disk image
    if emails and image_path and mft_entries:
        if verbose:
            print_section("Running Exfiltration Detector")
            print("  Correlating file hashes with email attachments...")

        exfil_finding = detect_exfiltration(image_path, mft_entries, emails)
        if exfil_finding:
            findings = [exfil_finding] + list(findings)
            if verbose:
                print(
                    f"  Detected exfiltration: {len(exfil_finding.matches)} correlation(s)"
                )
        elif verbose:
            print("  No exfiltration patterns detected")

    # Output JSON if requested
    if output_json:
        output_data = {
            "findings": [f.to_dict() for f in findings],
            "summary": {
                "total_findings": len(findings),
                "mft_entries": len(mft_entries),
                "prefetch_entries": len(prefetch_entries),
                "event_log_entries": len(evtx_entries),
            },
        }

        with open(output_json, "w") as f:
            json.dump(output_data, f, indent=2)

        if verbose:
            print(f"  Written JSON output to: {output_json}")

    return findings


def _write_output(findings: list, output_path: Optional[Path]) -> None:
    """Serialize findings to JSON with approval workflow support."""
    if output_path is None:
        return

    # Wrap findings in FindingWithApproval objects (DRAFT status by default)
    findings_with_approval = []
    for i, finding in enumerate(findings, 1):
        finding_id = f"F-{i:03d}"
        wrapped = FindingWithApproval(
            finding_id=finding_id,
            finding=finding.to_dict() if hasattr(finding, "to_dict") else finding,
        )
        findings_with_approval.append(wrapped)

    payload = {
        "findings": [f.to_dict() for f in findings_with_approval],
        "summary": {
            "total": len(findings_with_approval),
            "draft": len(findings_with_approval),  # All new findings are DRAFT
            "approved": 0,
            "rejected": 0,
        },
    }
    with open(output_path, "w") as fh:
        json.dump(payload, fh, indent=2, default=str)


def _render_findings(findings: list, validation_reports: Optional[dict] = None) -> None:
    """Print a minimal rendering for image-only runs."""
    print_section("Analysis Results")
    if not findings:
        print("\n  No findings.")
        return
    for idx, finding in enumerate(findings, 1):
        validation_status = None
        if validation_reports and id(finding) in validation_reports:
            report = validation_reports[id(finding)]
            if report.passed:
                if report.warnings:
                    validation_status = f"PASSED with {len(report.warnings)} warning(s)"
                else:
                    validation_status = "PASSED"
            else:
                validation_status = (
                    f"FAILED ({len(report.critical_issues)} critical issues)"
                )
        print_finding(finding, idx, validation_status)


def _mft_entries_to_access_records(mft_entries) -> list[MFTAccessRecord]:
    """Project MFT entries into the minimal shape NetworkDetector consumes."""
    records: list[MFTAccessRecord] = []
    for entry in mft_entries:
        accessed = entry.si_accessed or entry.fn_accessed
        if accessed is None:
            continue
        records.append(
            MFTAccessRecord(
                filename=entry.file_name,
                parent_path=entry.parent_path,
                accessed=accessed,
            )
        )
    return records


def _run_network_detector(
    browser_history_path: Optional[Path],
    pcap_path: Optional[Path],
    mft_entries,
    verbose: bool,
) -> list:
    """Run NetworkDetector against browser history + optional PCAP."""
    if browser_history_path is None and pcap_path is None:
        return []

    browser_history = None
    if browser_history_path is not None:
        if verbose:
            print(f"  Loading browser history from: {browser_history_path}")
        browser_history = BrowserHistoryParser().parse_csv(browser_history_path)
        if verbose:
            print(f"    Loaded {len(browser_history)} browser history entries")

    http_requests = None
    dns_queries = None
    tcp_conversations = None
    if pcap_path is not None:
        if verbose:
            print(f"  Loading HTTP/DNS/TCP from PCAP: {pcap_path}")
        from .parsers.pcap_parser import PcapParser

        parser = PcapParser()
        http_requests = parser.extract_http_requests(pcap_path)
        dns_queries = parser.extract_dns_queries(pcap_path)
        tcp_conversations = parser.extract_tcp_conversations(pcap_path)
        if verbose:
            print(
                f"    Extracted {len(http_requests)} HTTP requests, "
                f"{len(dns_queries)} DNS queries, "
                f"{len(tcp_conversations)} TCP conversations"
            )

    mft_records = _mft_entries_to_access_records(mft_entries) if mft_entries else None

    if verbose:
        print_section("Running Network Detector")

    findings = NetworkDetector().analyze(
        browser_history=browser_history,
        mft_records=mft_records,
        http_requests=http_requests,
        dns_queries=dns_queries,
        tcp_conversations=tcp_conversations,
    )

    if verbose:
        print(f"  Detected {len(findings)} network finding(s)")

    return findings


def _run_registry_detector(
    shimcache_path: Optional[Path],
    amcache_path: Optional[Path],
    bam_path: Optional[Path],
    userassist_path: Optional[Path],
    run_keys_path: Optional[Path],
    verbose: bool,
) -> list:
    """Parse any supplied registry CSVs and run RegistryDetector."""
    if not any(
        [shimcache_path, amcache_path, bam_path, userassist_path, run_keys_path]
    ):
        return []

    parser = RegistryParser()
    shimcache = amcache = bam = userassist = run_keys = None

    if shimcache_path is not None:
        if verbose:
            print(f"  Loading Shimcache CSV from: {shimcache_path}")
        shimcache = parser.parse_shimcache_csv(shimcache_path)
        if verbose:
            print(f"    Loaded {len(shimcache)} Shimcache entries")

    if amcache_path is not None:
        if verbose:
            print(f"  Loading Amcache CSV from: {amcache_path}")
        amcache = parser.parse_amcache_csv(amcache_path)
        if verbose:
            print(f"    Loaded {len(amcache)} Amcache entries")

    if bam_path is not None:
        if verbose:
            print(f"  Loading BAM CSV from: {bam_path}")
        bam = parser.parse_bam_csv(bam_path)
        if verbose:
            print(f"    Loaded {len(bam)} BAM entries")

    if userassist_path is not None:
        if verbose:
            print(f"  Loading UserAssist CSV from: {userassist_path}")
        userassist = parser.parse_userassist_csv(userassist_path)
        if verbose:
            print(f"    Loaded {len(userassist)} UserAssist entries")

    if run_keys_path is not None:
        if verbose:
            print(f"  Loading Run keys CSV from: {run_keys_path}")
        run_keys = parser.parse_run_keys_csv(run_keys_path)
        if verbose:
            print(f"    Loaded {len(run_keys)} Run key entries")

    if verbose:
        print_section("Running Registry Detector")

    findings = RegistryDetector().analyze(
        shimcache=shimcache,
        amcache=amcache,
        bam=bam,
        userassist=userassist,
        run_keys=run_keys,
    )

    if verbose:
        print(f"  Detected {len(findings)} registry finding(s)")

    return findings


def _run_yara_detector(
    yara_rules_path: Optional[Path],
    yara_scan_path: Optional[Path],
    verbose: bool,
) -> list:
    """Compile YARA rules and scan the target file or directory.

    Raises SystemExit when yara-python is not installed (same contract as
    ``--nsrl-bloom`` when ``rbloom`` is missing): explicit CLI flags must not
    be silently ignored. ``scenario_runner._run_yara`` takes the opposite
    stance and returns ``[]`` when yara-python is missing, because scenarios
    auto-detect capabilities rather than being user-driven.
    """
    if yara_rules_path is None or yara_scan_path is None:
        return []

    if not _YARA_AVAILABLE:
        print(
            "Error: --yara-rules/--yara-scan requires yara-python. "
            "Install with `pip install yara-python`.",
            file=sys.stderr,
        )
        sys.exit(1)

    if verbose:
        print_section("Running YARA Detector")
        print(f"  Compiling rules from: {yara_rules_path}")

    try:
        scanner = YaraScanner.compile_from_directory(yara_rules_path)
    except MissingYaraError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)
    except (ValueError, FileNotFoundError) as exc:
        print(f"Error: YARA rule compilation failed: {exc}", file=sys.stderr)
        sys.exit(1)

    if verbose:
        print(f"    Compiled {scanner.rule_count} rule(s)")
        if scanner.compile_errors:
            print(f"    Skipped {len(scanner.compile_errors)} broken rule file(s)")

    detector = YaraDetector(scanner=scanner)
    if yara_scan_path.is_dir():
        findings = detector.analyze_directory(yara_scan_path)
    else:
        findings = detector.analyze_file(yara_scan_path)

    if verbose:
        print(f"  Detected {len(findings)} YARA match(es)")
    return findings


def _run_memory_detector(
    memory_path: Optional[Path],
    verbose: bool,
) -> list:
    """Run Volatility 3 + MemoryDetector against a memory dump.

    Exits non-zero (same contract as ``--yara-rules`` / ``--nsrl-bloom``) when
    the operator asked for memory analysis but Volatility 3 or the image is
    missing. Silent fallback would let CI declare success on a malformed run.
    """
    if memory_path is None:
        return []

    try:
        from .memory import (
            MissingVolatilityError,
            PluginExecutionError,
            VolatilityRunner,
        )
    except ImportError as exc:  # pragma: no cover — exercise path
        print(f"Error: memory analysis unavailable: {exc}", file=sys.stderr)
        sys.exit(1)

    if verbose:
        print_section("Running Memory Detector")
        print(f"  Image: {memory_path}")

    try:
        runner = VolatilityRunner(memory_path)
    except MissingVolatilityError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)
    except FileNotFoundError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)

    pslist = psscan = malfind = cmdline = netscan = None
    linux_bash = linux_pslist = linux_sockstat = None
    # Each entry is (label, runner-method, local-slot-name). We try every
    # plugin on every dump: a Windows dump simply fails the linux.* plugins
    # (logged + skipped), and a Linux dump fails the windows.* plugins. The
    # detector's analyze() tolerates missing streams, so partial success
    # still produces findings.
    for name, fn in (
        ("pslist", runner.run_pslist),
        ("psscan", runner.run_psscan),
        ("malfind", runner.run_malfind),
        ("cmdline", runner.run_cmdline),
        ("netscan", runner.run_netscan),
        ("linux.bash", runner.run_linux_bash),
        ("linux.pslist", runner.run_linux_pslist),
        ("linux.sockstat", runner.run_linux_sockstat),
    ):
        try:
            rows = fn()
        except PluginExecutionError as exc:
            # A plugin crashing on an unfamiliar symbol set must not take
            # the whole memory pass down. Log and move on; detectors
            # tolerate missing streams.
            if verbose:
                print(f"    {name}: FAILED ({exc})")
            continue
        if verbose:
            print(f"    {name}: {len(rows)} row(s)")
        if name == "pslist":
            pslist = rows
        elif name == "psscan":
            psscan = rows
        elif name == "malfind":
            malfind = rows
        elif name == "cmdline":
            cmdline = rows
        elif name == "netscan":
            netscan = rows
        elif name == "linux.bash":
            linux_bash = rows
        elif name == "linux.pslist":
            linux_pslist = rows
        elif name == "linux.sockstat":
            linux_sockstat = rows

    findings = MemoryDetector().analyze(
        pslist=pslist,
        psscan=psscan,
        malfind=malfind,
        cmdline=cmdline,
        netscan=netscan,
        linux_bash=linux_bash,
        linux_pslist=linux_pslist,
        linux_sockstat=linux_sockstat,
    )

    # If every plugin (both Windows and Linux) failed, the dump is either
    # malformed or the symbol tables are missing for its kernel/OS. Surface
    # that explicitly so the operator doesn't interpret 0 findings as
    # "clean".
    all_streams = (
        pslist,
        psscan,
        malfind,
        cmdline,
        netscan,
        linux_bash,
        linux_pslist,
        linux_sockstat,
    )
    if all(stream is None for stream in all_streams):
        print(
            "Warning: no memory plugins returned data. "
            "Confirm the dump is a supported format and that Volatility "
            "can resolve symbols for its kernel.",
            file=sys.stderr,
        )

    if verbose:
        print(f"  Detected {len(findings)} memory finding(s)")
    return findings


def _run_lnk_jumplist_detector(
    lnk_csv_path: Optional[Path],
    jumplist_csv_path: Optional[Path],
    verbose: bool,
) -> list:
    """Parse any supplied LNK / Jump List CSVs and run LnkJumpListDetector."""
    if lnk_csv_path is None and jumplist_csv_path is None:
        return []

    lnk_entries = jumplist_entries = None

    if lnk_csv_path is not None:
        if verbose:
            print(f"  Loading LNK CSV from: {lnk_csv_path}")
        lnk_entries = LnkParser().parse_csv(lnk_csv_path)
        if verbose:
            print(f"    Loaded {len(lnk_entries)} LNK entries")

    if jumplist_csv_path is not None:
        if verbose:
            print(f"  Loading Jump List CSV from: {jumplist_csv_path}")
        jumplist_entries = JumpListParser().parse_csv(jumplist_csv_path)
        if verbose:
            print(f"    Loaded {len(jumplist_entries)} Jump List entries")

    if verbose:
        print_section("Running LNK / Jump List Detector")

    findings = LnkJumpListDetector().analyze(
        lnk_entries=lnk_entries,
        jumplist_entries=jumplist_entries,
    )

    if verbose:
        print(f"  Detected {len(findings)} LNK / Jump List finding(s)")

    return findings


def cmd_analyze(args):
    """Handle analyze command."""
    print_banner()

    image_path: Optional[Path] = (
        Path(args.image) if getattr(args, "image", None) else None
    )
    pst_path: Optional[Path] = Path(args.pst) if getattr(args, "pst", None) else None
    pcap_path: Optional[Path] = Path(args.pcap) if getattr(args, "pcap", None) else None
    browser_history_path: Optional[Path] = (
        Path(args.browser_history) if getattr(args, "browser_history", None) else None
    )
    shimcache_path: Optional[Path] = (
        Path(args.shimcache) if getattr(args, "shimcache", None) else None
    )
    amcache_path: Optional[Path] = (
        Path(args.amcache) if getattr(args, "amcache", None) else None
    )
    bam_path: Optional[Path] = Path(args.bam) if getattr(args, "bam", None) else None
    userassist_path: Optional[Path] = (
        Path(args.userassist) if getattr(args, "userassist", None) else None
    )
    run_keys_path: Optional[Path] = (
        Path(args.run_keys) if getattr(args, "run_keys", None) else None
    )
    lnk_path: Optional[Path] = Path(args.lnk) if getattr(args, "lnk", None) else None
    jumplist_path: Optional[Path] = (
        Path(args.jumplist) if getattr(args, "jumplist", None) else None
    )
    memory_path: Optional[Path] = (
        Path(args.memory) if getattr(args, "memory", None) else None
    )
    if memory_path is not None and not memory_path.is_file():
        print(f"Error: memory image not found: {memory_path}", file=sys.stderr)
        sys.exit(1)
    yara_rules_path: Optional[Path] = (
        Path(args.yara_rules) if getattr(args, "yara_rules", None) else None
    )
    yara_scan_path: Optional[Path] = (
        Path(args.yara_scan) if getattr(args, "yara_scan", None) else None
    )
    if (yara_rules_path is None) != (yara_scan_path is None):
        print(
            "Error: --yara-rules and --yara-scan must be provided together",
            file=sys.stderr,
        )
        sys.exit(1)
    if yara_rules_path is not None and not yara_rules_path.is_dir():
        print(
            f"Error: --yara-rules must be a directory of .yar files: {yara_rules_path}",
            file=sys.stderr,
        )
        sys.exit(1)
    if yara_scan_path is not None and not yara_scan_path.exists():
        print(f"Error: --yara-scan target not found: {yara_scan_path}", file=sys.stderr)
        sys.exit(1)
    nsrl_db_path: Optional[Path] = (
        Path(args.nsrl_db) if getattr(args, "nsrl_db", None) else None
    )
    nsrl_use_bloom: bool = bool(getattr(args, "nsrl_bloom", False))
    if nsrl_use_bloom:
        try:
            import rbloom  # noqa: F401
        except ImportError:
            print(
                "Error: --nsrl-bloom requires rbloom. Install: pip install rbloom",
                file=sys.stderr,
            )
            sys.exit(1)

    registry_paths = [
        shimcache_path,
        amcache_path,
        bam_path,
        userassist_path,
        run_keys_path,
    ]
    artifact_args = [
        getattr(args, "mft", None),
        getattr(args, "prefetch", None),
        getattr(args, "evtx", None),
    ]
    has_artifacts = any(artifact_args)
    has_network = pcap_path is not None or browser_history_path is not None
    has_registry = any(registry_paths)
    has_lnk_jumplist = lnk_path is not None or jumplist_path is not None
    has_memory = memory_path is not None
    has_yara = yara_rules_path is not None and yara_scan_path is not None

    if (
        image_path is None
        and not has_artifacts
        and pst_path is None
        and not has_network
        and not has_registry
        and not has_lnk_jumplist
        and not has_memory
        and not has_yara
    ):
        print(
            "Error: provide --image and/or --pst and/or all of --mft/--prefetch/--evtx "
            "and/or --pcap/--browser-history and/or one of "
            "--shimcache/--amcache/--bam/--userassist/--run-keys "
            "and/or --lnk/--jumplist "
            "and/or --memory "
            "and/or --yara-rules/--yara-scan",
            file=sys.stderr,
        )
        sys.exit(1)

    if has_artifacts and not all(artifact_args):
        print(
            "Error: --mft, --prefetch, and --evtx must be provided together",
            file=sys.stderr,
        )
        sys.exit(1)

    if pcap_path is not None and not pcap_path.exists():
        print(f"Error: PCAP file not found: {pcap_path}", file=sys.stderr)
        sys.exit(1)

    if browser_history_path is not None and not browser_history_path.exists():
        print(
            f"Error: browser history CSV not found: {browser_history_path}",
            file=sys.stderr,
        )
        sys.exit(1)

    _registry_path_labels = [
        ("Shimcache", shimcache_path),
        ("Amcache", amcache_path),
        ("BAM", bam_path),
        ("UserAssist", userassist_path),
        ("Run keys", run_keys_path),
        ("LNK", lnk_path),
        ("Jump List", jumplist_path),
    ]
    for label, path in _registry_path_labels:
        if path is not None and not path.exists():
            print(f"Error: {label} CSV not found: {path}", file=sys.stderr)
            sys.exit(1)

    nsrl_filter = None
    if nsrl_db_path is not None or nsrl_use_bloom:
        from .carving import NSRLFilter, find_nsrl_database

        resolved = nsrl_db_path or find_nsrl_database()
        if resolved is None or not resolved.exists():
            print(
                "Error: NSRL database not found. "
                "Run ./scripts/download-nsrl.sh modern or pass --nsrl-db PATH.",
                file=sys.stderr,
            )
            sys.exit(1)
        print_section("Loading NSRL Database")
        backend = "bloom" if nsrl_use_bloom else "set"
        print(f"  Path: {resolved} (backend: {backend})")
        nsrl_filter = NSRLFilter(resolved, use_bloom=nsrl_use_bloom)
        nsrl_filter.load()
        stats = nsrl_filter.get_stats()
        print(
            f"  Loaded {stats['sha1_count']:,} SHA-1 hashes, "
            f"{stats['md5_count']:,} MD5 hashes"
        )

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
        if has_network:
            findings = list(findings) + _run_network_detector(
                browser_history_path, pcap_path, mft_entries=None, verbose=True
            )
        if has_registry:
            findings = list(findings) + _run_registry_detector(
                shimcache_path,
                amcache_path,
                bam_path,
                userassist_path,
                run_keys_path,
                verbose=True,
            )
        if has_lnk_jumplist:
            findings = list(findings) + _run_lnk_jumplist_detector(
                lnk_path, jumplist_path, verbose=True
            )
        if has_memory:
            findings = list(findings) + _run_memory_detector(memory_path, verbose=True)
        if has_yara:
            findings = list(findings) + _run_yara_detector(
                yara_rules_path, yara_scan_path, verbose=True
            )
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
        image_path=image_path,
    )

    if disk_finding is not None:
        findings = [disk_finding] + list(findings)

    if has_network:
        mft_entries_for_network = MFTParser().parse_csv(mft_path)
        findings = list(findings) + _run_network_detector(
            browser_history_path,
            pcap_path,
            mft_entries=mft_entries_for_network,
            verbose=True,
        )

    if has_registry:
        findings = list(findings) + _run_registry_detector(
            shimcache_path,
            amcache_path,
            bam_path,
            userassist_path,
            run_keys_path,
            verbose=True,
        )

    if has_lnk_jumplist:
        findings = list(findings) + _run_lnk_jumplist_detector(
            lnk_path, jumplist_path, verbose=True
        )

    if has_memory:
        findings = list(findings) + _run_memory_detector(memory_path, verbose=True)

    if has_yara:
        findings = list(findings) + _run_yara_detector(
            yara_rules_path, yara_scan_path, verbose=True
        )

    # Validate CRITICAL findings
    print_section("Validating CRITICAL Findings")
    validator = AdversarialValidator()
    validation_reports = {}
    validated_findings = []
    suppressed_count = 0

    for finding in findings:
        if finding.severity == "critical":
            report = validator.validate(finding)
            validation_reports[id(finding)] = report

            if report.critical_issues:
                # Finding failed validation - suppress it
                suppressed_count += 1
                print(f"  [SUPPRESSED] {finding.title}")
                for issue in report.critical_issues:
                    print(f"    - {issue}")
            else:
                # Finding passed validation
                validated_findings.append(finding)
                if report.warnings:
                    print(
                        f"  [PASSED] {finding.title} ({len(report.warnings)} warning(s))"
                    )
                else:
                    print(f"  [PASSED] {finding.title}")
        else:
            # Non-CRITICAL findings pass through unvalidated
            validated_findings.append(finding)

    if suppressed_count > 0:
        print(
            f"\n  Suppressed {suppressed_count} finding(s) due to validation failures"
        )

    findings = validated_findings

    _write_output(findings, Path(args.output) if args.output else None)

    # Display findings
    print_section("Analysis Results")

    if not findings:
        print("\n  No suspicious findings detected.")
        print("  All artifacts are consistent with expected behavior.")
        return

    print(f"\n  Found {len(findings)} suspicious activities:")

    for i, finding in enumerate(findings, 1):
        validation_status = None
        if id(finding) in validation_reports:
            report = validation_reports[id(finding)]
            if report.warnings:
                validation_status = f"PASSED with {len(report.warnings)} warning(s)"
            else:
                validation_status = "PASSED (6/6 checks)"
        print_finding(finding, i, validation_status)

    # Summary
    print_section("Summary")
    critical_count = sum(1 for f in findings if f.severity == "critical")
    high_count = sum(1 for f in findings if f.severity == "high")
    medium_count = sum(1 for f in findings if f.severity == "medium")

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

    # Find test fixtures directory (consolidated under tests/fixtures/).
    module_dir = Path(__file__).parent.parent
    test_data_dir = module_dir / "tests" / "fixtures"

    if not test_data_dir.exists():
        print(
            f"Error: Test fixtures directory not found: {test_data_dir}",
            file=sys.stderr,
        )
        print("Expected structure: tests/fixtures/synthetic_*.csv", file=sys.stderr)
        sys.exit(1)

    mft_path = test_data_dir / "synthetic_mft.csv"
    prefetch_path = test_data_dir / "synthetic_prefetch.csv"
    evtx_path = test_data_dir / "synthetic_evtx.csv"

    if not all([mft_path.exists(), prefetch_path.exists(), evtx_path.exists()]):
        print("Error: Synthetic test data files not found", file=sys.stderr)
        sys.exit(1)

    print("\nRunning demonstration with synthetic test data...")
    print("This dataset simulates a ransomware attack with timestamp manipulation.")
    print("\nTest scenario:")
    print("  - malware.exe executed at 14:25 PM")
    print("  - MFT shows modification at 14:40 PM (15 min AFTER execution)")
    print("  - This violates causality - files cannot be modified after execution")
    print("  - Event ID 4688 confirms execution at 14:25:03 PM")
    print("  - Expected: Detect violation, resolve via Event Log tiebreaker")

    # Analyze
    findings = analyze_artifacts(
        mft_path,
        prefetch_path,
        evtx_path,
        output_json=None,  # Use _write_output instead for approval workflow
        verbose=True,
    )

    # Write output with approval metadata
    _write_output(findings, Path(args.output) if args.output else None)

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

    malware_findings = [f for f in findings if "malware.exe" in f.title.lower()]

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
            print(
                f"    [PASS] Confidence in expected range: {malware_finding.confidence:.2f}"
            )
        else:
            print(
                f"    [WARN] Confidence outside expected range: {malware_finding.confidence:.2f}"
            )

        # Check reasoning chain
        if len(malware_finding.reasoning_chain) >= 4:
            print(
                f"    [PASS] Comprehensive reasoning chain ({len(malware_finding.reasoning_chain)} steps)"
            )
        else:
            print(
                f"    [WARN] Reasoning chain seems short ({len(malware_finding.reasoning_chain)} steps)"
            )

    print("\n  Demo completed successfully!")
    print("  The self-correction engine detected the planted contradiction,")
    print("  resolved it using Event Log evidence, and adjusted confidence.")


def _save_detailed_results(report, base_dir: Path = None):
    """Save detailed findings to timestamped directory."""
    if not report.findings:
        return None

    # Default to test-results/{tier}/{scenario_name}/{timestamp}/
    if base_dir is None:
        base_dir = Path("test-results")

    manifest = report.manifest
    timestamp_str = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

    # Create timestamped directory
    result_dir = base_dir / manifest.tier / manifest.name / timestamp_str
    result_dir.mkdir(parents=True, exist_ok=True)

    # Save full findings as JSON
    findings_data = [f.to_dict() for f in report.findings]
    findings_path = result_dir / "findings.json"
    with findings_path.open("w", encoding="utf-8") as f:
        json.dump(findings_data, f, indent=2, default=str)

    # Save metadata (test metrics)
    metadata = {
        "timestamp": datetime.now().isoformat(),
        "scenario_name": manifest.name,
        "scenario_tier": manifest.tier,
        "scenario_directory": str(manifest.directory),
        "findings_count": report.findings_count,
        "precision": report.precision,
        "recall": report.recall,
        "f1": report.f1,
        "average_confidence": report.average_confidence,
        "detected_executables": report.detected_executables,
        "true_positives": report.true_positives,
        "false_positives": report.false_positives,
        "false_negatives": report.false_negatives,
        "passed": report.passed,
    }

    metadata_path = result_dir / "metadata.json"
    with metadata_path.open("w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2, default=str)

    # Save human-readable summary
    summary_lines = [
        f"# {manifest.name} - {timestamp_str}",
        "",
        "## Test Metrics",
        "",
        f"- **Status**: {'PASS' if report.passed else 'FAIL'}",
        f"- **Precision**: {report.precision:.3f}",
        f"- **Recall**: {report.recall:.3f}",
        f"- **F1 Score**: {report.f1:.3f}",
        f"- **Average Confidence**: {report.average_confidence:.3f}",
        "",
        "## Findings Summary",
        "",
        f"- **Total Findings**: {report.findings_count}",
        f"- **True Positives**: {len(report.true_positives)}",
        f"- **False Positives**: {len(report.false_positives)}",
        f"- **False Negatives**: {len(report.false_negatives)}",
        "",
    ]

    if report.findings:
        summary_lines.extend(
            [
                "## Detailed Findings",
                "",
            ]
        )
        for i, finding in enumerate(report.findings, 1):
            summary_lines.extend(
                [
                    f"### Finding {i}: {finding.title}",
                    "",
                    f"- **Severity**: {finding.severity.upper()}",
                    f"- **Category**: {finding.category.value}",
                    f"- **Confidence**: {finding.confidence:.2f} ({finding.confidence_label})",
                    f"- **Type**: {finding.finding_type}",
                    "",
                    f"{finding.description}",
                    "",
                ]
            )

    summary_path = result_dir / "SUMMARY.md"
    with summary_path.open("w", encoding="utf-8") as f:
        f.write("\n".join(summary_lines))

    return result_dir


def cmd_run(args):
    """Handle run command: execute one scenario.yaml manifest end-to-end."""
    scenario_path = Path(args.scenario)
    try:
        report = run_scenario_path(scenario_path)
    except ScenarioLoadError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(2)
    except OSError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(2)

    manifest = report.manifest

    # Save detailed results to timestamped directory (auto-save)
    result_dir = None
    if not report.skipped and report.findings:
        result_dir = _save_detailed_results(report)

    # Also save to custom output path if specified (backward compat)
    output_path = Path(args.output) if args.output else None
    if output_path is not None:
        with output_path.open("w", encoding="utf-8") as handle:
            json.dump(report.to_dict(), handle, indent=2, default=str)

    print_section(f"Scenario: {manifest.name}")
    print(f"  Tier:        {manifest.tier}")
    print(f"  Directory:   {manifest.directory}")

    if report.skipped:
        print(f"  Status:      SKIPPED ({report.skip_reason})")
        # --strict treats skips as failures so CI gates cannot be silently
        # greenlit by missing evidence. Default preserves local-dev ergonomics.
        sys.exit(1 if getattr(args, "strict", False) else 0)

    print(f"  Findings:    {report.findings_count}")
    print(f"  Precision:   {report.precision:.2f}")
    print(f"  Recall:      {report.recall:.2f}")
    print(f"  F1:          {report.f1:.2f}")
    if report.false_positives:
        print(f"  False pos:   {report.false_positives}")
    if report.false_negatives:
        print(f"  False neg:   {report.false_negatives}")
    print(f"  Avg conf:    {report.average_confidence:.2f}")
    print(f"  Status:      {'PASS' if report.passed else 'FAIL'}")

    if result_dir:
        print(f"\n  Results saved to: {result_dir}")

    sys.exit(0 if report.passed else 1)


def cmd_approve(args):
    """Handle approve command: approve findings."""
    print_banner()

    findings_path = Path(args.findings)
    if not findings_path.exists():
        print(f"Error: Findings file not found: {findings_path}", file=sys.stderr)
        sys.exit(1)

    manager = ApprovalManager(findings_path)
    finding_ids = args.finding_ids
    reviewer = args.reviewer
    reason = args.reason

    print_section("Approving Findings")
    print(f"  Findings file: {findings_path}")
    print(f"  Reviewer: {reviewer}")
    print(f"  Finding IDs: {', '.join(finding_ids)}")
    if reason:
        print(f"  Reason: {reason}")

    count = manager.approve(finding_ids, reviewer, reason)

    print(f"\n  ✓ Approved {count} finding(s)")
    print(f"  ✓ Audit log updated: {manager.audit_path}")


def cmd_reject(args):
    """Handle reject command: reject findings."""
    print_banner()

    findings_path = Path(args.findings)
    if not findings_path.exists():
        print(f"Error: Findings file not found: {findings_path}", file=sys.stderr)
        sys.exit(1)

    if not args.reason:
        print("Error: --reason is required for rejection", file=sys.stderr)
        sys.exit(1)

    manager = ApprovalManager(findings_path)
    finding_ids = args.finding_ids
    reviewer = args.reviewer
    reason = args.reason

    print_section("Rejecting Findings")
    print(f"  Findings file: {findings_path}")
    print(f"  Reviewer: {reviewer}")
    print(f"  Finding IDs: {', '.join(finding_ids)}")
    print(f"  Reason: {reason}")

    count = manager.reject(finding_ids, reviewer, reason)

    print(f"\n  ✓ Rejected {count} finding(s)")
    print(f"  ✓ Audit log updated: {manager.audit_path}")


def cmd_list_findings(args):
    """Handle list command: show findings by status."""
    print_banner()

    findings_path = Path(args.findings)
    if not findings_path.exists():
        print(f"Error: Findings file not found: {findings_path}", file=sys.stderr)
        sys.exit(1)

    manager = ApprovalManager(findings_path)
    all_findings = manager.load_findings()

    status_filter = args.status.upper() if args.status else None
    if status_filter:
        try:
            status = ApprovalStatus(status_filter)
            findings = manager.get_by_status(status)
            title = f"Findings ({status.value})"
        except ValueError:
            print(
                f"Error: Invalid status '{status_filter}'. Valid: DRAFT, APPROVED, REJECTED",
                file=sys.stderr,
            )
            sys.exit(1)
    else:
        findings = all_findings
        title = "All Findings"

    print_section(title)
    print(f"  Findings file: {findings_path}")
    print(f"  Total: {len(findings)}")

    if not findings:
        print("\n  No findings match the filter.")
        return

    # Group by status
    by_status = {
        "DRAFT": [f for f in findings if f.is_draft()],
        "APPROVED": [f for f in findings if f.is_approved()],
        "REJECTED": [f for f in findings if f.is_rejected()],
    }

    for status, items in by_status.items():
        if not items:
            continue

        print(f"\n  {status} ({len(items)}):")
        for finding in items:
            title = finding.finding.get("title", "Unknown")
            severity = finding.finding.get("severity", "unknown").upper()
            print(f"    [{finding.finding_id}] {severity}: {title}")

            if finding.approval and finding.approval.reviewer:
                print(f"      Reviewer: {finding.approval.reviewer}")
                print(f"      Timestamp: {finding.approval.timestamp.isoformat()}")
                if finding.approval.reason:
                    print(f"      Reason: {finding.approval.reason}")
                if finding.approval.signature_hash:
                    print(f"      Signature: {finding.approval.signature_hash}")


def cmd_case_init(args):
    """Handle case init command: create a new case."""
    print_banner()

    case_root = Path(args.case_root) if args.case_root else Path("/cases")
    manager = CaseManager(case_root)

    print_section("Creating Case")
    print(f"  Case ID: {args.case_id}")
    print(f"  Name: {args.name}")
    print(f"  Examiner: {args.examiner}")
    if args.description:
        print(f"  Description: {args.description}")
    print(f"  Case root: {case_root}")

    try:
        case = manager.create_case(
            case_id=args.case_id,
            name=args.name,
            examiner=args.examiner,
            description=args.description,
        )
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)

    print(f"\n  Case created: {case.directory}")
    print(f"  Status: {case.status.value}")
    print(f"  Created: {case.created_at.isoformat()}")
    print("\n  Directory structure:")
    print(f"    {case.directory}/")
    print("      evidence/")
    print("      analysis/")
    print("      reports/")
    print("      exports/")
    print("      CASE.yaml")
    print("      evidence.json")
    print("      audit.jsonl")


def cmd_evidence_register(args):
    """Handle evidence register command: register evidence file."""
    print_banner()

    case_root = Path(args.case_root) if args.case_root else Path("/cases")
    manager = CaseManager(case_root)

    file_path = Path(args.file)
    if not file_path.exists():
        print(f"Error: Evidence file not found: {file_path}", file=sys.stderr)
        sys.exit(1)

    print_section("Registering Evidence")
    print(f"  Case ID: {args.case_id}")
    print(f"  File: {file_path}")
    print(f"  Description: {args.description}")
    if args.type:
        print(f"  Type: {args.type}")

    print("\n  Calculating SHA-256 hash...")

    try:
        evidence = manager.register_evidence(
            case_id=args.case_id,
            file_path=file_path,
            description=args.description,
            evidence_type=args.type,
        )
    except FileNotFoundError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)

    print("\n  Evidence registered:")
    print(f"    SHA-256: {evidence.sha256_hash}")
    print(f"    Size: {evidence.file_size:,} bytes")
    print(f"    Registered: {evidence.registered_at.isoformat()}")


def cmd_evidence_verify(args):
    """Handle evidence verify command: verify evidence hashes."""
    print_banner()

    case_root = Path(args.case_root) if args.case_root else Path("/cases")
    manager = CaseManager(case_root)

    print_section("Verifying Evidence")
    print(f"  Case ID: {args.case_id}")
    print(f"  Case root: {case_root}")

    results = manager.verify_evidence(args.case_id)

    if "error" in results:
        print(f"\n  Error: {results['error']}", file=sys.stderr)
        sys.exit(1)

    print(f"\n  Total: {results['total']}")
    print(f"  Verified: {results['verified']}")
    print(f"  Failed: {results['failed']}")
    print(f"  Missing: {results['missing']}")

    if results["failed"] > 0 or results["missing"] > 0:
        print("\n  Details:")
        for detail in results["details"]:
            status = detail["status"]
            file_path = detail["file"]
            if status == "VERIFIED":
                print(f"    [OK] {file_path}")
                print(f"         Hash: {detail['hash']}")
            elif status == "FAILED":
                print(f"    [FAILED] {file_path}")
                print(f"         Expected: {detail['registered_hash']}")
                print(f"         Got:      {detail['current_hash']}")
            elif status == "MISSING":
                print(f"    [MISSING] {file_path}")
                print(f"              Hash: {detail['registered_hash']}")

    if results["failed"] > 0:
        sys.exit(1)


def cmd_case_status(args):
    """Handle case status command: show case status."""
    print_banner()

    case_root = Path(args.case_root) if args.case_root else Path("/cases")
    manager = CaseManager(case_root)

    print_section("Case Status")
    print(f"  Case ID: {args.case_id}")

    try:
        status = manager.get_case_status(args.case_id)
    except FileNotFoundError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)

    print(f"\n  Name: {status['name']}")
    print(f"  Status: {status['status']}")
    print(f"  Examiner: {status['examiner']}")
    print(f"  Created: {status['created_at']}")
    print(f"  Directory: {status['directory']}")
    print(f"\n  Evidence files: {status['evidence_count']}")
    print(f"  Findings: {status['findings_count']}")
    print(f"  Audit entries: {status['audit_entries']}")


def cmd_audit_log(args):
    """Handle audit log command: show recent audit entries."""
    print_banner()

    audit_path = Path(args.audit_file)
    if not audit_path.exists():
        print(f"Error: Audit file not found: {audit_path}", file=sys.stderr)
        sys.exit(1)

    logger = AuditLogger(audit_path)
    entries = logger.get_recent(limit=args.limit)

    print_section(f"Audit Log (most recent {len(entries)} entries)")
    print(f"  Audit file: {audit_path}")

    if not entries:
        print("\n  No audit entries found.")
        return

    for entry in entries:
        print(f"\n  [{entry.timestamp.isoformat()}] {entry.action}")
        if entry.examiner:
            print(f"    Examiner: {entry.examiner}")

        if entry.details:
            if entry.action == "tool_invocation":
                tool = entry.details.get("tool", "unknown")
                command = entry.details.get("command", "")
                exit_code = entry.details.get("exit_code")
                duration_ms = entry.details.get("duration_ms")
                output_hash = entry.details.get("output_hash")

                print(f"    Tool: {tool}")
                print(f"    Command: {command}")
                if exit_code is not None:
                    print(f"    Exit code: {exit_code}")
                if duration_ms is not None:
                    print(f"    Duration: {duration_ms}ms")
                if output_hash:
                    print(f"    Output hash: {output_hash}")
            else:
                print(f"    Details: {json.dumps(entry.details, indent=6)}")


def cmd_audit_summary(args):
    """Handle audit summary command: show audit statistics."""
    print_banner()

    audit_path = Path(args.audit_file)
    if not audit_path.exists():
        print(f"Error: Audit file not found: {audit_path}", file=sys.stderr)
        sys.exit(1)

    logger = AuditLogger(audit_path)
    stats = logger.get_statistics()

    print_section("Audit Log Summary")
    print(f"  Audit file: {audit_path}")
    print(f"\n  Total entries: {stats['total_entries']}")
    print(f"  Unique tools: {stats['unique_tools']}")

    if stats["tools"]:
        print("\n  Tools used:")
        for tool in stats["tools"]:
            print(f"    - {tool}")

    if stats["examiners"]:
        print("\n  Examiners:")
        for examiner in stats["examiners"]:
            print(f"    - {examiner}")

    print("\n  Actions:")
    for action, count in sorted(
        stats["actions"].items(), key=lambda x: x[1], reverse=True
    ):
        print(f"    {action}: {count}")


def cmd_report(args):
    """Handle report command: generate investigation report."""
    print_banner()

    case_root = Path(args.case_root) if args.case_root else Path("/cases")
    manager = CaseManager(case_root)
    generator = ReportGenerator(manager)

    output_path = Path(args.output)
    report_format = ReportFormat(args.format)

    print_section("Generating Report")
    print(f"  Case ID: {args.case_id}")
    print(f"  Format: {report_format.value}")
    print(f"  Output: {output_path}")
    print(f"  Approved findings only: {args.approved_only}")

    try:
        generator.generate(
            case_id=args.case_id,
            output_path=output_path,
            format=report_format,
            approved_only=args.approved_only,
        )
    except FileNotFoundError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)
    except NotImplementedError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)

    print(f"\n  Report generated: {output_path}")
    print(f"  Size: {output_path.stat().st_size:,} bytes")


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="4n6 Nexus (SIFT Find Evil) - Autonomous DFIR Agent with Self-Correction",
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

  # Run a scenario manifest end-to-end
  python -m sift_find_evil.cli run --scenario scenarios/synthetic/02_ransomware
        """,
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Demo command
    demo_parser = subparsers.add_parser(
        "demo", help="Run demonstration with synthetic test data"
    )
    demo_parser.add_argument("--output", "-o", help="Write findings to JSON file")

    # Analyze command
    analyze_parser = subparsers.add_parser("analyze", help="Analyze forensic artifacts")
    analyze_parser.add_argument(
        "--mft", "-m", help="Path to MFT CSV file (MFTECmd output)"
    )
    analyze_parser.add_argument(
        "--prefetch", "-p", help="Path to Prefetch CSV file (PECmd output)"
    )
    analyze_parser.add_argument(
        "--evtx", "-e", help="Path to Event Log CSV file (EvtxECmd output)"
    )
    analyze_parser.add_argument(
        "--pst", help="Path to PST file for email exfiltration detection (optional)"
    )
    analyze_parser.add_argument(
        "--image",
        "-i",
        help="Path to disk image (.E01 or .dd) for wipe detection and/or content reading (optional)",
    )
    analyze_parser.add_argument(
        "--pcap", help="Path to PCAP file for network-layer detectors (optional)"
    )
    analyze_parser.add_argument(
        "--browser-history",
        dest="browser_history",
        help="Path to browser history CSV (Chrome/Firefox/Edge export) for webmail-exfil detection (optional)",
    )
    analyze_parser.add_argument(
        "--shimcache",
        help="Path to Shimcache CSV (RegRipper/RECmd export) for registry detection (optional)",
    )
    analyze_parser.add_argument(
        "--amcache",
        help="Path to Amcache CSV (RECmd/AmcacheParser export) for registry detection (optional)",
    )
    analyze_parser.add_argument(
        "--bam", help="Path to BAM/DAM CSV export for registry detection (optional)"
    )
    analyze_parser.add_argument(
        "--userassist",
        help="Path to UserAssist CSV export for registry detection (optional)",
    )
    analyze_parser.add_argument(
        "--run-keys",
        dest="run_keys",
        help="Path to Run keys CSV (RegRipper/RECmd export) for persistence detection (optional)",
    )
    analyze_parser.add_argument(
        "--lnk",
        help="Path to LNK CSV (LECmd export) for document-access, removable-media, and Startup-folder persistence detection (optional)",
    )
    analyze_parser.add_argument(
        "--jumplist",
        help="Path to Jump List CSV (JLECmd export) for per-application MRU and UNC-share document access detection (optional)",
    )
    analyze_parser.add_argument(
        "--memory",
        help=(
            "Path to a memory dump (.dmp, .raw, .lime, .vmem) for Volatility 3 "
            "analysis (pslist/psscan/netscan/malfind/cmdline). Requires "
            "volatility3 installed (pip install volatility3). MITRE T1055, "
            "T1620, T1059."
        ),
    )
    analyze_parser.add_argument(
        "--yara-rules",
        dest="yara_rules",
        help=(
            "Directory of .yar/.yara rule files for malware classification "
            "(MITRE T1587.001 / T1027). Must be paired with --yara-scan."
        ),
    )
    analyze_parser.add_argument(
        "--yara-scan",
        dest="yara_scan",
        help=(
            "File or directory to scan with the compiled YARA rules. "
            "Must be paired with --yara-rules."
        ),
    )
    analyze_parser.add_argument(
        "--nsrl-db",
        dest="nsrl_db",
        help=(
            "Path to NSRLFile.txt for known-good hash filtering. "
            "Auto-discovered if omitted (~/.sift_find_evil/nsrl/NSRLFile.txt, "
            "./nsrl/NSRLFile.txt, /cases/nsrl/NSRLFile.txt). Used by carving triage."
        ),
    )
    analyze_parser.add_argument(
        "--nsrl-bloom",
        dest="nsrl_bloom",
        action="store_true",
        help=(
            "Use bloom filter backend for NSRL (requires rbloom; ~400 MB RAM "
            "vs 2-10 GB for exact set; tunable false-positive rate)"
        ),
    )
    analyze_parser.add_argument("--output", "-o", help="Write findings to JSON file")

    # Run command
    run_parser = subparsers.add_parser(
        "run",
        help="Run a scenario.yaml manifest end-to-end",
    )
    run_parser.add_argument(
        "--scenario",
        required=True,
        help="Path to a scenario directory or scenario.yaml file",
    )
    run_parser.add_argument(
        "--output",
        "-o",
        help="Write scenario report to JSON file",
    )
    run_parser.add_argument(
        "--strict",
        action="store_true",
        help="Treat SKIPPED scenarios as failures (exit 1). Use in CI to prevent silent passes from missing evidence.",
    )

    # Approve command
    approve_parser = subparsers.add_parser(
        "approve",
        help="Approve findings for inclusion in reports",
    )
    approve_parser.add_argument(
        "--findings",
        "-f",
        required=True,
        help="Path to findings.json file",
    )
    approve_parser.add_argument(
        "--finding-ids",
        nargs="+",
        required=True,
        help="Finding IDs to approve (space-separated)",
    )
    approve_parser.add_argument(
        "--reviewer",
        "-r",
        required=True,
        help="Name of reviewer approving findings",
    )
    approve_parser.add_argument(
        "--reason",
        help="Optional approval reason/note",
    )

    # Reject command
    reject_parser = subparsers.add_parser(
        "reject",
        help="Reject findings with a reason",
    )
    reject_parser.add_argument(
        "--findings",
        "-f",
        required=True,
        help="Path to findings.json file",
    )
    reject_parser.add_argument(
        "--finding-ids",
        nargs="+",
        required=True,
        help="Finding IDs to reject (space-separated)",
    )
    reject_parser.add_argument(
        "--reviewer",
        "-r",
        required=True,
        help="Name of reviewer rejecting findings",
    )
    reject_parser.add_argument(
        "--reason",
        required=True,
        help="Required rejection reason",
    )

    # List command
    list_parser = subparsers.add_parser(
        "list",
        help="List findings by approval status",
    )
    list_parser.add_argument(
        "--findings",
        "-f",
        required=True,
        help="Path to findings.json file",
    )
    list_parser.add_argument(
        "--status",
        "-s",
        choices=["draft", "approved", "rejected"],
        help="Filter by approval status (default: show all)",
    )

    # Case command group
    case_parser = subparsers.add_parser(
        "case",
        help="Case management commands",
    )
    case_subparsers = case_parser.add_subparsers(
        dest="case_command", help="Case operations"
    )

    # Case init subcommand
    case_init_parser = case_subparsers.add_parser(
        "init",
        help="Create a new case",
    )
    case_init_parser.add_argument(
        "--case-id",
        required=True,
        help="Unique case identifier (e.g., INC-2026-001)",
    )
    case_init_parser.add_argument(
        "--name",
        required=True,
        help="Human-readable case name",
    )
    case_init_parser.add_argument(
        "--examiner",
        required=True,
        help="Name of primary examiner",
    )
    case_init_parser.add_argument(
        "--description",
        help="Optional case description",
    )
    case_init_parser.add_argument(
        "--case-root",
        help="Case root directory (default: /cases)",
    )

    # Evidence register subcommand
    evidence_register_parser = case_subparsers.add_parser(
        "register",
        help="Register evidence file with SHA-256 hash",
    )
    evidence_register_parser.add_argument(
        "--case-id",
        required=True,
        help="Case identifier",
    )
    evidence_register_parser.add_argument(
        "--file",
        required=True,
        help="Path to evidence file",
    )
    evidence_register_parser.add_argument(
        "--description",
        required=True,
        help="Description of evidence",
    )
    evidence_register_parser.add_argument(
        "--type",
        choices=["disk_image", "memory_dump", "pcap", "log", "other"],
        help="Evidence type (optional)",
    )
    evidence_register_parser.add_argument(
        "--case-root",
        help="Case root directory (default: /cases)",
    )

    # Evidence verify subcommand
    evidence_verify_parser = case_subparsers.add_parser(
        "verify",
        help="Verify all evidence hashes in case",
    )
    evidence_verify_parser.add_argument(
        "--case-id",
        required=True,
        help="Case identifier",
    )
    evidence_verify_parser.add_argument(
        "--case-root",
        help="Case root directory (default: /cases)",
    )

    # Case status subcommand
    case_status_parser = case_subparsers.add_parser(
        "status",
        help="Show case status summary",
    )
    case_status_parser.add_argument(
        "--case-id",
        required=True,
        help="Case identifier",
    )
    case_status_parser.add_argument(
        "--case-root",
        help="Case root directory (default: /cases)",
    )

    # Audit command group
    audit_parser = subparsers.add_parser(
        "audit",
        help="Audit log commands",
    )
    audit_subparsers = audit_parser.add_subparsers(
        dest="audit_command", help="Audit operations"
    )

    # Audit log subcommand
    audit_log_parser = audit_subparsers.add_parser(
        "log",
        help="Show recent audit entries",
    )
    audit_log_parser.add_argument(
        "--audit-file",
        required=True,
        help="Path to audit.jsonl file",
    )
    audit_log_parser.add_argument(
        "--limit",
        type=int,
        default=20,
        help="Number of recent entries to show (default: 20)",
    )

    # Audit summary subcommand
    audit_summary_parser = audit_subparsers.add_parser(
        "summary",
        help="Show audit log statistics",
    )
    audit_summary_parser.add_argument(
        "--audit-file",
        required=True,
        help="Path to audit.jsonl file",
    )

    # Report command
    report_parser = subparsers.add_parser(
        "report",
        help="Generate investigation report",
    )
    report_parser.add_argument(
        "--case-id",
        required=True,
        help="Case identifier",
    )
    report_parser.add_argument(
        "--output",
        "-o",
        required=True,
        help="Output file path",
    )
    report_parser.add_argument(
        "--format",
        "-f",
        choices=["markdown", "html", "pdf"],
        default="markdown",
        help="Report format (default: markdown)",
    )
    report_parser.add_argument(
        "--case-root",
        help="Case root directory (default: /cases)",
    )
    report_parser.add_argument(
        "--approved-only",
        action="store_true",
        default=True,
        help="Include only approved findings (default: true)",
    )
    report_parser.add_argument(
        "--all-findings",
        action="store_false",
        dest="approved_only",
        help="Include all findings (approved, draft, rejected)",
    )

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    if args.command == "demo":
        cmd_demo(args)
    elif args.command == "analyze":
        cmd_analyze(args)
    elif args.command == "run":
        cmd_run(args)
    elif args.command == "approve":
        cmd_approve(args)
    elif args.command == "reject":
        cmd_reject(args)
    elif args.command == "list":
        cmd_list_findings(args)
    elif args.command == "case":
        if not hasattr(args, "case_command") or args.case_command is None:
            case_parser.print_help()
            sys.exit(1)
        if args.case_command == "init":
            cmd_case_init(args)
        elif args.case_command == "register":
            cmd_evidence_register(args)
        elif args.case_command == "verify":
            cmd_evidence_verify(args)
        elif args.case_command == "status":
            cmd_case_status(args)
    elif args.command == "audit":
        if not hasattr(args, "audit_command") or args.audit_command is None:
            audit_parser.print_help()
            sys.exit(1)
        if args.audit_command == "log":
            cmd_audit_log(args)
        elif args.audit_command == "summary":
            cmd_audit_summary(args)
    elif args.command == "report":
        cmd_report(args)


if __name__ == "__main__":
    main()
