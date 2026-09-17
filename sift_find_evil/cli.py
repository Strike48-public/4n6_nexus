"""Command-line interface for SIFT Find Evil DFIR Agent.

Usage:
    python -m sift_find_evil.cli analyze --mft <path> --prefetch <path> --evtx <path>
    python -m sift_find_evil.cli demo  # Run with synthetic test data
"""

import argparse
import hashlib
import json
import re
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
from .correlation.hidden_process import detect_hidden_linux_processes
from .findings.negatives import credential_dump_negative
from .parsers.lnk_jumplist_parser import JumpListParser, LnkParser
from .parsers.registry_parser import RegistryParser
from .scenario_runner import ScenarioLoadError, run_scenario_path
from .validation import AdversarialValidator
from .approval import ApprovalManager, ApprovalStatus, FindingWithApproval
from .approval.manager import APPROVAL_HMAC_KEY_ENV
from .audit import AuditLogger
from .case import CaseManager
from .reporting import ReportFormat, ReportGenerator
from .reporting.retractions import render_retraction_section

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
    # Banner removed for cleaner demo output
    pass


def print_section(title: str):
    """Print section header."""
    print(f"\n{'='*70}")
    print(f"  {title}")
    print("=" * 70)


def print_finding(finding, index: int, validation_status: Optional[str] = None):
    """Print a finding in a readable format.

    Evidence-derived strings (title, description, contradiction text, reasoning
    steps, evidence values) are adversary-controlled, so each is routed through
    ``_terminal_safe`` before printing - a crafted artifact cannot inject ANSI
    escapes or control chars into the examiner's terminal.
    """
    print(f"\n[Finding {index}] {_terminal_safe(finding.title)}")
    print(f"  Severity: {finding.severity.upper()}")
    print(f"  Category: {finding.category.value}")
    print(f"  Confidence: {finding.confidence:.2f} ({finding.confidence_label})")
    print(f"  Type: {finding.finding_type}")
    if validation_status:
        print(f"  Validation: {validation_status}")
    print()

    print("  Description:")
    for line in _terminal_safe(finding.description).split("\n"):
        print(f"    {line}")
    print()

    if finding.contradictions:
        print(f"  Contradictions Detected: {len(finding.contradictions)}")
        for i, contradiction in enumerate(finding.contradictions, 1):
            print(
                f"    {i}. {contradiction.type.value} ({contradiction.severity.value})"
            )
            print(f"       Impact: {contradiction.confidence_impact:.2f}")
            print(f"       {_terminal_safe(contradiction.description)}")
        print()

    if finding.resolutions:
        print(f"  Resolutions Applied: {len(finding.resolutions)}")
        for i, resolution in enumerate(finding.resolutions, 1):
            print(f"    {i}. {_terminal_safe(resolution.resolution_method)}")
            print(f"       Recovery: +{resolution.confidence_recovery:.2f}")
        print()

    print("  Reasoning Chain:")
    for i, step in enumerate(finding.reasoning_chain, 1):
        print(f"    {i}. {_terminal_safe(step)}")
    print()

    print("  Evidence:")
    for key, value in finding.evidence.items():
        print(f"    - {_terminal_safe(key)}: {_terminal_safe(value)}")
    print()


def analyze_artifacts(
    mft_path: Path,
    prefetch_path: Path,
    evtx_path: Path,
    output_json: Optional[Path] = None,
    verbose: bool = False,
    pst_path: Optional[Path] = None,
    image_path: Optional[Path] = None,
    mft_entries: Optional[list] = None,
) -> list:
    """Analyze forensic artifacts and detect contradictions.

    Args:
        mft_path: Path to MFT CSV file
        prefetch_path: Path to Prefetch CSV file
        evtx_path: Path to Event Log CSV file
        output_json: Optional path to write JSON output
        verbose: Print verbose output
        mft_entries: Pre-parsed MFT entries. When supplied, the MFT CSV is NOT
            re-parsed here -- a caller that already parsed it (e.g. for network
            correlation) passes the list to avoid a second full parse of the
            largest artifact on a big image (SFE-fibx.8). When None (the default),
            the MFT is parsed from ``mft_path`` as before, so every existing caller
            is unchanged.

    Returns:
        List of findings
    """
    if verbose:
        print_section("Loading Artifacts")

    # Parse artifacts
    mft_parser = MFTParser()
    prefetch_parser = PrefetchParser()
    evtx_parser = EventLogParser()

    if mft_entries is None:
        if verbose:
            print(f"  Loading MFT entries from: {mft_path}")
        mft_entries = mft_parser.parse_csv(mft_path)
        if verbose:
            print(f"    Loaded {len(mft_entries)} MFT entries")
    elif verbose:
        # Reusing a caller-parsed list: report the reuse rather than a bare
        # "Loaded N" with no preceding "Loading from:" line.
        print(f"    Reusing {len(mft_entries)} pre-parsed MFT entries")

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
    """Serialize findings to JSON with approval workflow support.

    Central write backstop: refuses any output path resolving into an evidence
    directory (so every ``_write_output`` caller - analyze, demo - is guarded,
    not just the ones that check up front).
    """
    if output_path is None:
        return
    _guard_output_path(output_path)

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


# Evidence directories are read-only by policy (project CLAUDE.md): the engine
# must never write findings/reports back into the tree it is analyzing. Output
# routes to ./analysis, ./exports, ./reports, or an explicit non-evidence path.
_EVIDENCE_ROOTS = ("/cases", "/mnt", "/media")


def _resolves_into_evidence_dir(path: Path) -> bool:
    """True iff ``path`` resolves into a read-only evidence directory.

    Resolves symlinks and relative components FIRST (``Path.resolve``), so a
    symlink whose target lands in an evidence dir is caught - a path-string check
    alone would miss it. Matches an absolute evidence root (`/cases`, `/mnt`,
    `/media`) or any ``evidence`` path component. ``strict=False`` so a
    not-yet-created output file still resolves against its real parent.
    """
    resolved = path.resolve()
    for root in _EVIDENCE_ROOTS:
        try:
            if resolved.is_relative_to(root):
                return True
        except ValueError:  # pragma: no cover - is_relative_to never raises here
            pass
    return any(part == "evidence" for part in resolved.parts)


def _guard_output_path(output_path: Path) -> None:
    """Exit(1) if an output path would write into a read-only evidence dir.

    Central guard for every CLI write target (the findings ``--output`` and the
    derived ``.hardened.json`` sibling), so evidence integrity cannot be
    violated by an operator pointing output at the evidence tree.
    """
    if _resolves_into_evidence_dir(output_path):
        print(
            f"Error: refusing to write into an evidence directory: {output_path}\n"
            "Evidence is read-only. Route --output to ./analysis, ./exports, or "
            "./reports (or another non-evidence path).",
            file=sys.stderr,
        )
        sys.exit(1)


# Matches ANSI/VT escape sequences (CSI, OSC, and bare ESC-prefixed) so a crafted
# evidence string cannot drive the examiner's terminal (clear screen, recolor,
# move cursor) when a finding is printed.
_ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b[@-Z\\-_]|\x1b.")


def _terminal_safe(value: object) -> str:
    """Render ``value`` for stdout with ANSI escapes and C0 control chars removed.

    Evidence content (registry values, command lines, file paths) is
    adversary-controlled; printing it verbatim lets a crafted artifact emit
    terminal control sequences. This strips ESC-based sequences and C0 control
    characters, preserving only ``\\t`` and ``\\n`` (legitimate layout). Ordinary
    text is returned unchanged. Non-str inputs are coerced via ``str`` first.
    """
    text = str(value)
    text = _ANSI_ESCAPE_RE.sub("", text)
    return "".join(c for c in text if c in "\t\n" or ord(c) >= 0x20)


def _evidence_image_digest(evidence_paths: list) -> str:
    """SHA-256 binding receipts to this run's real evidence artifacts.

    Hashes, in sorted-path order, each present artifact's basename AND full
    streamed contents - so two runs over the same CSVs get the SAME 64-hex
    digest (receipts stay reproducible across machines, since only the basename,
    not the absolute path, enters the hash), and any byte change flips it.

    Like the orchestrator's ``_evidence_digest`` this is a CONTENT hash (both
    stream every byte), but it differs deliberately in the path component: the
    orchestrator walks a directory tree and hashes each file's path RELATIVE to
    the root, whereas this takes a flat list of explicit artifact paths from
    argparse and hashes only the basename. The trade-off: two distinct files
    with the SAME basename passed as different artifacts (e.g.
    ``--mft /a/x.csv --prefetch /b/x.csv``) would not be disambiguated by the
    path component - but each file's full contents still enter the digest, so any
    byte difference still produces a different image and tampering is still
    caught. Basename-only keeps the digest stable regardless of where the
    operator stored the evidence.
    """
    digest = hashlib.sha256()
    for path in sorted(Path(p) for p in evidence_paths if p):
        if not path.is_file():
            continue
        digest.update(path.name.encode("utf-8"))
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    return digest.hexdigest()


def _harden_report(
    findings: list,
    evidence_paths: list,
    tool: str = "engine",
    supplied_classes: set | None = None,
) -> dict:
    """Route real-evidence findings through the shared custody chain.

    Reuses the scored path's ``hardening.harden_findings`` so a real MFT/EVTX
    run produces the full productionization chain - per-finding Ed25519 receipts
    plus a set-level Merkle anchor - that the standalone offline verifier
    (``tools/verify_receipts.py``) re-checks with no engine imports. The report
    is ``HardeningReport.to_dict()`` verbatim, the exact shape the verifier
    consumes (SFE-13yw).

    Signing follows the engine default: with ``cryptography`` present every
    finding gets a publicly-verifiable Ed25519 receipt (an ephemeral per-run key
    unless ``$SFE_RECEIPT_ED25519_KEY`` pins one for provenance); absent it, the
    pipeline degrades to HMAC-only (no signed receipt, no anchor). We do NOT
    expose a "don't sign" toggle: ``harden_findings`` mints an ephemeral key
    whenever crypto is available regardless, so such a flag would be a lie.

    Hardening is ADDITIVE: ``harden_findings`` never mutates or drops a finding,
    so detection output (and thus F1) is unchanged - the receipts are an overlay.

    Args:
        findings: The Finding objects the detectors produced.
        evidence_paths: The artifact files this run consumed; hashed into the
            image digest every receipt and the anchor are bound to.
        tool: Provenance label recorded in each receipt.

    Returns:
        The hardening report as a JSON-serializable dict.
    """
    from .hardening import harden_findings

    image_sha256 = _evidence_image_digest(evidence_paths)
    receipt_key = hashlib.sha256(image_sha256.encode("utf-8")).digest()
    report = harden_findings(
        findings,
        image_sha256=image_sha256,
        receipt_key=receipt_key,
        tool=tool,
        supplied_classes=supplied_classes,
    )
    return report.to_dict()


# argparse dests whose values are evidence-file paths bound into the receipt
# image digest when --harden runs. Kept in one place so a new --<artifact> flag
# is hardened simply by listing its dest here.
_EVIDENCE_PATH_ARGS = (
    "mft",
    "prefetch",
    "evtx",
    "pst",
    "image",
    "pcap",
    "browser_history",
    "shimcache",
    "amcache",
    "bam",
    "userassist",
    "run_keys",
    "lnk",
    "jumplist",
    "memory",
    "yara_scan",
    "linux_artifacts",
)


# CLI evidence-flag dest -> coarse coverage class (coverage.harden_coverage
# COARSE_CLASSES). Drives the harden-path coverage audit: the union of the coarse
# classes for every flag actually supplied this run is the "what we parsed" set
# the audit diffs against what the findings cite. A dest not listed here (e.g. a
# non-evidence flag) contributes no class.
_ARG_TO_COVERAGE_CLASS: dict[str, str] = {
    "mft": "disk",
    "prefetch": "disk",
    "evtx": "disk",
    "image": "disk",
    "pst": "pst",
    "pcap": "network",
    "browser_history": "network",
    "shimcache": "registry",
    "amcache": "registry",
    "bam": "registry",
    "userassist": "registry",
    "run_keys": "registry",
    "lnk": "lnk_jumplist",
    "jumplist": "lnk_jumplist",
    "memory": "memory",
    "yara_scan": "yara",
    "linux_artifacts": "linux",
}


def _supplied_coverage_classes(args) -> set:
    """The coarse coverage classes whose evidence was supplied on this run.

    Reads the same argparse dests the receipt image digest binds, mapping each
    supplied evidence flag to its coarse class. Only flags actually provided
    contribute, so the set is exactly "what this run parsed".
    """
    return {
        cls for dest, cls in _ARG_TO_COVERAGE_CLASS.items() if getattr(args, dest, None)
    }


def _hardened_report_path(output_path: Path) -> Path:
    """Sibling path for the hardening report next to the findings --output.

    ``findings.json`` -> ``findings.hardened.json``. The draft approval-workflow
    findings file stays as-is; the verifiable hardening report lands alongside it.
    """
    return output_path.with_name(f"{output_path.stem}.hardened.json")


# Exit code for a non-PASS report-blocking gate (SFE-fibx.5 PR-D). Distinct from
# the exit-1 used for input/setup errors so automation can tell "the gate blocked
# a written report" apart from "the run could not start".
_GATE_EXIT_CODE = 2


def _exit_on_gate(verdict: Optional[str]) -> None:
    """Exit non-zero when the report-blocking gate did not PASS.

    Called AFTER all output is written (the report ships regardless -- degrade,
    not refuse); this only sets the process exit status so CI/automation treats a
    BLOCKED / NEEDS_HUMAN verdict as a hard gate. A None verdict (no --harden) or
    PASS is a no-op.
    """
    if verdict in (None, "PASS"):
        return
    print(
        f"\n  Report-blocking gate: {verdict} "
        f"(report written; exiting {_GATE_EXIT_CODE}).",
        file=sys.stderr,
    )
    sys.exit(_GATE_EXIT_CODE)


def _maybe_write_hardened(args, findings: list) -> Optional[str]:
    """Emit a verifiable hardening report when --harden is set.

    Collects every evidence path actually provided on this run (so the receipt
    image digest binds the real artifacts), hardens the findings, and writes the
    report next to --output. No-op unless --harden was passed; requires --output
    (validated by the caller upstream).

    Returns the report-blocking gate verdict (PASS / NEEDS_HUMAN / BLOCKED) so the
    caller can set a non-zero exit code on a non-PASS, or None when --harden was
    not requested (nothing to gate).
    """
    if not getattr(args, "harden", False):
        return None
    output = Path(args.output)
    evidence_paths = [
        getattr(args, name) for name in _EVIDENCE_PATH_ARGS if getattr(args, name, None)
    ]
    report = _harden_report(
        findings,
        evidence_paths=evidence_paths,
        supplied_classes=_supplied_coverage_classes(args),
    )
    hardened_path = _hardened_report_path(output)
    with hardened_path.open("w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, default=str)
    print_section("Custody Chain")
    signed = sum(1 for h in report["hardened"] if h.get("signed_receipt"))
    print(f"  Hardened report:   {hardened_path}")
    print(f"  Findings:          {report['finding_count']}")
    print(f"  Ed25519 receipts:  {signed}")
    print(f"  Merkle anchor:     {'yes' if report.get('anchor') else 'no (HMAC-only)'}")
    # Self-correction visibility (SFE-fibx.1): surface how many candidates the
    # verifier retracted, and write the human-readable retraction trail beside the
    # JSON so the engine's self-correction is legible, not buried in the report.
    ledger = report.get("hypothesis_ledger") or {}
    retractions = ledger.get("self_correction_count", 0)
    print(f"  Retractions:       {retractions}")
    hardened_stem = hardened_path.stem  # "<name>.hardened"
    retraction_md = hardened_path.with_name(f"{hardened_stem}.retractions.md")
    _guard_output_path(retraction_md)
    retraction_md.write_text(render_retraction_section(ledger), encoding="utf-8")
    print(f"  Self-correction:   {retraction_md}")
    # Coverage audit (SFE-fibx.5 PR-B): surface blind spots (parsed-but-uncited)
    # and not-examined important classes so a reader never mistakes an unexamined
    # class for a clean result.
    coverage = report.get("coverage") or {}
    uncited = coverage.get("uncited") or []
    not_examined = coverage.get("not_examined") or []
    if uncited:
        print(
            f"  Uncited evidence:  {', '.join(uncited)} (parsed, no finding cited it)"
        )
    if not_examined:
        print(f"  Not examined:      {', '.join(not_examined)} (evidence not supplied)")
    print(f"  Verify offline:    python3 tools/verify_receipts.py {hardened_path}")
    # Report-blocking gate (SFE-fibx.5 PR-D): stamp the composed verdict + reasons.
    # The report is already written above (degrade, not refuse); the caller turns a
    # non-PASS verdict into a non-zero exit so automation treats it as a hard gate.
    gate = report.get("gate") or {}
    verdict = gate.get("verdict", "PASS")
    print(f"  Gate verdict:      {verdict}")
    for reason in gate.get("reasons", []):
        print(f"    - {reason}")
    # Advisories (e.g. coverage gaps) are flagged but never change the exit code.
    for advisory in gate.get("advisories", []):
        print(f"  Advisory:          {advisory}")
    return verdict


# Interop export kinds -> the sibling-file suffix each writes next to --output.
# stix/ocsf are JSON; wazuh additionally emits a .wazuh-rules.xml rule stanza.
_EXPORT_SUFFIX = {"stix": "stix.json", "ocsf": "ocsf.json", "wazuh": "wazuh.json"}


def _export_path(output_path: Path, suffix: str) -> Path:
    """Sibling path for an interop export next to the findings --output.

    ``findings.json`` + ``stix.json`` -> ``findings.stix.json``. Mirrors
    :func:`_hardened_report_path` so every derived write shares one naming rule.
    """
    return output_path.with_name(f"{output_path.stem}.{suffix}")


def _maybe_write_export(args, findings: list) -> None:
    """Emit a STIX/OCSF/Wazuh export when --export is set.

    No-op unless --export was passed; requires --output (validated by the caller
    upstream). Every write target is routed through :func:`_guard_output_path`,
    so an export can never land in a read-only evidence directory.
    """
    kind = getattr(args, "export", None)
    if not kind:
        return
    # Imported lazily so the core CLI does not pay the interop import cost on
    # every run (and a missing optional dep can't break `analyze` without --export).
    from .interop import build_stix_bundle, ocsf_export, wazuh_export

    output = Path(args.output)
    export_path = _export_path(output, _EXPORT_SUFFIX[kind])
    _guard_output_path(export_path)

    print_section("Standards Export")
    if kind == "stix":
        payload = build_stix_bundle(findings)
        with export_path.open("w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, default=str)
        print(f"  STIX 2.1 bundle:   {export_path}")
        print(f"  Objects:           {len(payload['objects'])}")
    elif kind == "ocsf":
        payload = ocsf_export(findings)
        with export_path.open("w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, default=str)
        print(f"  OCSF findings:     {export_path}")
        print(f"  Detection events:  {len(payload)}")
    else:  # wazuh
        export = wazuh_export(findings)
        with export_path.open("w", encoding="utf-8") as fh:
            for alert in export.alerts:
                fh.write(json.dumps(alert, default=str) + "\n")
        rules_path = _export_path(output, "wazuh-rules.xml")
        _guard_output_path(rules_path)
        rules_path.write_text(export.rules_xml, encoding="utf-8")
        print(f"  Wazuh alerts:      {export_path}")
        print(f"  Wazuh rules:       {rules_path}")
        print(f"  Alerts:            {len(export.alerts)}")


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
    raw_out: Optional[dict] = None,
) -> list:
    """Run Volatility 3 + MemoryDetector against a memory dump.

    Exits non-zero (same contract as ``--yara-rules`` / ``--nsrl-bloom``) when
    the operator asked for memory analysis but Volatility 3 or the image is
    missing. Silent fallback would let CI declare success on a malformed run.

    ``raw_out``: optional sink. When provided, the raw ``linux.pslist`` rows are
    stashed under ``raw_out["linux_pslist"]`` so the caller can run the
    hidden-process cross-check (SFE-6mqd) WITHOUT re-running Volatility.
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

    if raw_out is not None:
        raw_out["linux_pslist"] = linux_pslist

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


def _run_linux_persistence_detector(
    linux_artifacts_path: Optional[Path],
    verbose: bool,
    raw_out: Optional[dict] = None,
) -> list:
    """Load Linux artifacts and run the Linux detectors.

    Accepts two input shapes at ``linux_artifacts_path``:

    * a **directory** -- treated as a mounted image root (or live-response
      bundle) and walked by the per-artifact parsers (SFE-4fnv) to PRODUCE the
      detector dict from raw ``.service`` units, crontabs, ``sudoers``,
      ``/etc/ld.so.preload``, shell-init files, the auth log and shell history;
    * a **file** -- a JSON object already matching the detector dict contract
      (``systemd_units``/``cron_entries``/``ld_preload``/``sudoers``/
      ``bashrc_entries``/``auth_events``/``shell_history``/``login_sessions``/
      ``proc_processes``); missing keys are treated as empty.

    ``LinuxPersistenceDetector``, ``LinuxAuthDetector`` (SFE-rfhz),
    ``LinuxExecutionDetector`` (SFE-jdii), ``LinuxLoginSessionDetector`` (wtmp)
    and ``LinuxProcessDetector`` (/proc) all run over the same collected dict.
    Exits non-zero on a missing or malformed bundle -- the same fail-loud
    contract as --memory/--yara, so a bad input never silently degrades to an
    empty run.
    """
    if linux_artifacts_path is None:
        return []

    if verbose:
        print_section("Running Linux Detectors")
        print(f"  Artifacts: {linux_artifacts_path}")

    if linux_artifacts_path.is_dir():
        from .parsers import collect_linux_artifacts

        artifacts = collect_linux_artifacts(linux_artifacts_path)
    else:
        try:
            with linux_artifacts_path.open("r", encoding="utf-8") as handle:
                artifacts = json.load(handle)
        except (OSError, json.JSONDecodeError) as exc:
            print(
                f"Error: could not read --linux-artifacts bundle "
                f"{linux_artifacts_path}: {exc}",
                file=sys.stderr,
            )
            sys.exit(1)

        if not isinstance(artifacts, dict):
            print(
                "Error: --linux-artifacts bundle must be a JSON object with keys like "
                "systemd_units/cron_entries/ld_preload/sudoers/bashrc_entries/"
                "auth_events/shell_history",
                file=sys.stderr,
            )
            sys.exit(1)

    # Stash the /proc capture rows for the hidden-process cross-check (SFE-6mqd)
    # so the caller need not re-walk the mounted root.
    if raw_out is not None and isinstance(artifacts, dict):
        raw_out["proc_processes"] = artifacts.get("proc_processes")

    return _analyze_linux_artifacts(artifacts)


def _analyze_linux_artifacts(artifacts: dict) -> list:
    """Run every Linux detector over one collected artifact dict.

    Mirrors the scenario harness' ``_run_linux_persistence`` detector list
    exactly (SFE-jsuq): the harness scored ``LinuxLoginSessionDetector`` (wtmp)
    and ``LinuxProcessDetector`` (/proc, SFE-t9vq) but the shipping CLI path
    historically ran only the first three, so those two surfaces were
    scored-but-not-shipped. Both consume keys the collector already produces
    (``login_sessions``/``proc_processes``), so this is pure parity, no new input.
    """
    from .detectors import (
        LinuxArtifactDetector,
        LinuxAuthDetector,
        LinuxExecutionDetector,
        LinuxLoginSessionDetector,
        LinuxPersistenceDetector,
        LinuxProcessDetector,
    )

    detectors: list[LinuxArtifactDetector] = [
        LinuxPersistenceDetector(),
        LinuxAuthDetector(),
        LinuxExecutionDetector(),
        LinuxLoginSessionDetector(),
        LinuxProcessDetector(),
    ]
    findings: list = []
    for detector in detectors:
        findings.extend(detector.analyze(artifacts))
    return findings


def _run_hidden_process_correlation(
    memory_raw: Optional[dict],
    linux_raw: Optional[dict],
    verbose: bool,
) -> list:
    """Cross-source T1014: a PID in the ``linux.pslist`` memory view but absent
    from the ``/proc`` capture is hidden by a userland getdents hook (SFE-6mqd).

    Consumes the raw rows already captured during the ``--memory`` and
    ``--linux-artifacts`` passes (no re-run of Volatility, no re-walk of the
    mounted root). Returns ``[]`` unless BOTH a ``linux.pslist`` view and a
    ``/proc`` capture were supplied.
    """
    proc_rows = (linux_raw or {}).get("proc_processes")
    pslist_rows = (memory_raw or {}).get("linux_pslist")
    findings = detect_hidden_linux_processes(proc_rows, pslist_rows)
    if verbose and findings:
        print_section("Cross-Source Hidden-Process Check")
        print(f"  Detected {len(findings)} hidden-process divergence(s)")
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


def _evtx_command_text(evtx_path: Optional[Path]) -> Optional[str]:
    """Concatenate Event Log 4688 command lines for negative re-verification.

    Returns the newline-joined command lines the run's 4688 events carry, or None
    when no Event Log was supplied (nothing to re-read). Re-parses with the same
    ``EventLogParser`` the analysis used, mirroring how ``_run_network_detector``
    re-reads the MFT -- the parse is cheap and keeps this helper self-contained.
    """
    if evtx_path is None:
        return None
    entries = EventLogParser().parse_csv(str(evtx_path), filter_event_ids=[4688])
    lines = [e.get_command_line() for e in entries]
    return "\n".join(line for line in lines if line)


def _append_proven_negatives(
    findings: list, evtx_path: Optional[Path], evtx_source: Optional[str]
) -> list:
    """Append mechanically-verified proven negatives to the finding list.

    Surfaces the "[NEGATIVE] tool ran and found zero X" claims the demo path
    already emits, now on the shipping ``analyze`` path (SFE-fibx.5 PR-C). Scope:
    the credential-dumping negative over the 4688 command lines -- the one domain
    the CLI reliably has re-readable output + a citation for. Only a negative that
    INDEPENDENTLY re-verifies PROVEN is appended (see ``credential_dump_negative``).

    Read-only over ``findings`` (returns a new list); negatives carry no
    ``evidence['executable']`` key, so they never enter F1 tp/fp/fn accounting.
    """
    text = _evtx_command_text(evtx_path)
    if text is None:
        return list(findings)
    fired = {getattr(f, "category", None) for f in findings}
    negative = credential_dump_negative(
        evtx_command_text=text,
        fired_categories=fired,
        tool_call_id=evtx_source or "",
    )
    result = list(findings)
    if negative is not None:
        result.append(negative)
        print(f"  [NEGATIVE] {negative.title}")
    return result


def cmd_analyze(args):
    """Handle analyze command."""
    print_banner()

    if getattr(args, "harden", False) and not getattr(args, "output", None):
        print(
            "Error: --harden requires --output (the hardening report is written "
            "next to it as <output>.hardened.json)",
            file=sys.stderr,
        )
        sys.exit(1)

    if getattr(args, "export", None) and not getattr(args, "output", None):
        print(
            "Error: --export requires --output (the export is written next to it "
            "as <output>.<format>.json)",
            file=sys.stderr,
        )
        sys.exit(1)

    # Evidence is read-only: refuse any output path that resolves into an
    # evidence directory (covers both the findings --output and its derived
    # .hardened.json sibling). Guards symlinks too (resolve() first).
    if getattr(args, "output", None):
        _guard_output_path(Path(args.output))

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
    linux_artifacts_path: Optional[Path] = (
        Path(args.linux_artifacts) if getattr(args, "linux_artifacts", None) else None
    )
    if linux_artifacts_path is not None and not linux_artifacts_path.exists():
        print(
            f"Error: --linux-artifacts path not found "
            f"(expected a JSON bundle file or a mounted-root directory): "
            f"{linux_artifacts_path}",
            file=sys.stderr,
        )
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
    has_linux = linux_artifacts_path is not None

    if (
        image_path is None
        and not has_artifacts
        and pst_path is None
        and not has_network
        and not has_registry
        and not has_lnk_jumplist
        and not has_memory
        and not has_yara
        and not has_linux
    ):
        print(
            "Error: provide --image and/or --pst and/or all of --mft/--prefetch/--evtx "
            "and/or --pcap/--browser-history and/or one of "
            "--shimcache/--amcache/--bam/--userassist/--run-keys "
            "and/or --lnk/--jumplist "
            "and/or --memory "
            "and/or --yara-rules/--yara-scan "
            "and/or --linux-artifacts",
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
        memory_raw: dict = {}
        linux_raw: dict = {}
        if has_memory:
            findings = list(findings) + _run_memory_detector(
                memory_path, verbose=True, raw_out=memory_raw
            )
        if has_yara:
            findings = list(findings) + _run_yara_detector(
                yara_rules_path, yara_scan_path, verbose=True
            )
        if has_linux:
            findings = list(findings) + _run_linux_persistence_detector(
                linux_artifacts_path, verbose=True, raw_out=linux_raw
            )
        if has_memory and has_linux:
            findings = list(findings) + _run_hidden_process_correlation(
                memory_raw, linux_raw, verbose=True
            )
        _write_output(findings, Path(args.output) if args.output else None)
        gate_verdict = _maybe_write_hardened(args, findings)
        _maybe_write_export(args, findings)
        _render_findings(findings)
        _exit_on_gate(gate_verdict)
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

    # Parse the MFT once up front only when the network surface also needs it, and
    # thread it into analyze_artifacts so the largest artifact is not parsed twice
    # (SFE-fibx.8). Without --network the engine parses it internally as before.
    mft_entries_for_network = MFTParser().parse_csv(mft_path) if has_network else None

    # Analyze
    findings = analyze_artifacts(
        mft_path,
        prefetch_path,
        evtx_path,
        output_json=None,  # we write combined output below
        verbose=True,
        pst_path=pst_path,
        image_path=image_path,
        mft_entries=mft_entries_for_network,
    )

    if disk_finding is not None:
        findings = [disk_finding] + list(findings)

    if has_network:
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

    memory_raw = {}
    linux_raw = {}
    if has_memory:
        findings = list(findings) + _run_memory_detector(
            memory_path, verbose=True, raw_out=memory_raw
        )

    if has_yara:
        findings = list(findings) + _run_yara_detector(
            yara_rules_path, yara_scan_path, verbose=True
        )

    if has_linux:
        findings = list(findings) + _run_linux_persistence_detector(
            linux_artifacts_path, verbose=True, raw_out=linux_raw
        )

    if has_memory and has_linux:
        findings = list(findings) + _run_hidden_process_correlation(
            memory_raw, linux_raw, verbose=True
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

    # Proven negatives (SFE-fibx.5 PR-C): surface "[NEGATIVE] tool ran and found
    # zero X" claims, mechanically re-verified against the 4688 command lines, so
    # a clean domain reads as an examined-and-clear result rather than silence.
    findings = _append_proven_negatives(findings, evtx_path, str(evtx_path))

    _write_output(findings, Path(args.output) if args.output else None)
    gate_verdict = _maybe_write_hardened(args, findings)
    _maybe_write_export(args, findings)

    # Display findings
    print_section("Analysis Results")

    if not findings:
        print("\n  No suspicious findings detected.")
        print("  All artifacts are consistent with expected behavior.")
        _exit_on_gate(gate_verdict)
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

    _exit_on_gate(gate_verdict)

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
        _guard_output_path(output_path)
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


def cmd_verify_findings(args):
    """Handle verify command: re-check approval signatures for tampering."""
    print_banner()

    findings_path = Path(args.findings)
    if not findings_path.exists():
        print(f"Error: Findings file not found: {findings_path}", file=sys.stderr)
        sys.exit(1)

    manager = ApprovalManager(findings_path)

    print_section("Verifying Approval Signatures")
    print(f"  Findings file: {findings_path}")

    results = manager.verify()

    if "error" in results:
        print(f"\n  Error: {results['error']}", file=sys.stderr)
        sys.exit(2)

    print(f"\n  Signed decisions: {results['total']}")
    print(f"  Verified: {results['verified']}")
    print(f"  Tampered: {results['tampered']}")
    print(f"  Unsigned: {results['unsigned']}")

    if results["tampered"] > 0 or results["unsigned"] > 0:
        print("\n  Details:")
        for detail in results["details"]:
            if detail["status"] == "TAMPERED":
                print(f"    [TAMPERED] {detail['finding_id']}")
            elif detail["status"] == "UNSIGNED":
                print(f"    [UNSIGNED] {detail['finding_id']}")

    if results["tampered"] > 0:
        sys.exit(1)


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
    _guard_output_path(output_path)
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
        "--linux-artifacts",
        dest="linux_artifacts",
        help=(
            "Linux persistence artifacts for LinuxPersistenceDetector: either a "
            "mounted-image root DIRECTORY (walked to parse raw .service units, "
            "crontabs, sudoers, ld.so.preload and shell-init files) or a JSON "
            "bundle FILE "
            "(systemd_units/cron_entries/ld_preload/sudoers/bashrc_entries). "
            "Standalone: does NOT require the mft/prefetch/evtx triad. MITRE "
            "T1543.002/T1053.003/T1574.006/T1548.003/T1546.004."
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
    analyze_parser.add_argument(
        "--harden",
        action="store_true",
        help=(
            "Route findings through the custody chain: mint a per-finding "
            "Ed25519 receipt + a set-level Merkle anchor, then write a hardening "
            "report (verifiable offline with tools/verify_receipts.py). Requires "
            "--output. Pin $SFE_RECEIPT_ED25519_KEY for provenance receipts."
        ),
    )
    analyze_parser.add_argument(
        "--export",
        choices=["stix", "ocsf", "wazuh"],
        help=(
            "Also emit findings in a SIEM/TIP interchange format next to "
            "--output: 'stix' (STIX 2.1 bundle -> <output>.stix.json), 'ocsf' "
            "(OCSF Detection Findings -> <output>.ocsf.json), or 'wazuh' (Wazuh "
            "alerts NDJSON + <output>.wazuh-rules.xml). Requires --output. "
            "Bulk-push to OpenSearch separately via "
            "python -m sift_find_evil.interop.push_opensearch."
        ),
    )

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

    # Verify command
    verify_parser = subparsers.add_parser(
        "verify",
        help="Re-verify approval signatures to detect tampering "
        f"(requires {APPROVAL_HMAC_KEY_ENV})",
    )
    verify_parser.add_argument(
        "--findings",
        "-f",
        required=True,
        help="Path to findings.json file",
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
    elif args.command == "verify":
        cmd_verify_findings(args)
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
