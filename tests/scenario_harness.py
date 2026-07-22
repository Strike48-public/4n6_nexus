"""Run all scenarios and compute precision / recall / F1 metrics.

Scenarios are discovered automatically from ``scenarios/**/scenario.yaml``
manifests that declare ``fixtures.mft``, ``fixtures.prefetch``, and
``fixtures.evtx`` inputs. Manifests without those fixtures (for example E01
or PCAP scenarios in ``real/`` and ``training/``) are skipped here because
they require disk-level parsing outside this harness.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import yaml

from sift_find_evil.hardening import HardeningReport, harden_findings
from sift_find_evil.detectors import NetworkDetector
from sift_find_evil.detectors.memory_detector import MemoryDetector
from sift_find_evil.detectors.registry_detector import RegistryDetector
from sift_find_evil.detectors.webmail_exfil_detector import MFTAccessRecord
from sift_find_evil.memory.volatility_runner import (
    _to_bash_history_row,
    _to_cmdline_row,
    _to_injection_row,
    _to_linux_network_row,
    _to_linux_process_row,
    _to_network_row,
    _to_process_row,
)
from sift_find_evil.detectors.lateral_movement_detector import (
    LateralMovementDetector,
)
from sift_find_evil.parsers.browser_history_parser import BrowserHistoryParser
from sift_find_evil.parsers.evtx_parser import EventLogParser
from sift_find_evil.parsers.mft_parser import MFTParser
from sift_find_evil.parsers.prefetch_parser import PrefetchParser
from sift_find_evil.parsers.registry_parser import RegistryParser
from sift_find_evil.self_correction.engine import Finding, SelfCorrectionEngine

try:
    from sift_find_evil.detectors.yara_detector import YaraDetector
    from sift_find_evil.yara_scan.scanner import MissingYaraError, YaraScanner

    _YARA_AVAILABLE = True
except ImportError:  # pragma: no cover — hosts without libyara
    YaraDetector = None  # type: ignore[assignment]
    YaraScanner = None  # type: ignore[assignment]
    MissingYaraError = RuntimeError  # type: ignore[assignment,misc]
    _YARA_AVAILABLE = False


@dataclass(frozen=True)
class ScenarioExpectation:
    """Expected ground truth for a scenario."""

    name: str
    directory: Path
    malicious_executables: frozenset[str]
    description: str
    mft_fixture: str
    prefetch_fixture: str
    evtx_fixture: str
    browser_history_fixture: Optional[str] = None
    shimcache_fixture: Optional[str] = None
    amcache_fixture: Optional[str] = None
    bam_fixture: Optional[str] = None
    userassist_fixture: Optional[str] = None
    run_keys_fixture: Optional[str] = None
    yara_rules_fixture: Optional[str] = None
    yara_scan_dir_fixture: Optional[str] = None
    memory_fixtures: dict[str, str] = field(default_factory=dict)
    finding_counts: dict[str, int] = field(default_factory=dict)
    # Benign artifacts PRESENT in this scenario's evidence that the engine must
    # NOT flag. Declared under manifest ``expected.false_positive_traps``; feed
    # the hallucination/abstention benchmark so it proves specificity, not just
    # recall. Empty for scenarios that declare none.
    false_positive_traps: frozenset[str] = field(default_factory=frozenset)


@dataclass
class ScenarioResult:
    """Aggregated result for one scenario."""

    name: str
    findings_count: int
    detected_executables: list[str]
    true_positives: list[str] = field(default_factory=list)
    false_positives: list[str] = field(default_factory=list)
    false_negatives: list[str] = field(default_factory=list)
    average_confidence: float = 0.0
    # Additive hardening metadata (receipts, verdict clamp, tool-semantics,
    # MITRE) for this scenario's findings. Populated by run_scenario via the
    # shared pipeline so the recall path carries the same guarantees as the
    # orchestrator; None only for a result built without hardening.
    hardening: Optional["HardeningReport"] = None

    @property
    def precision(self) -> float:
        """Return precision metric (TP / (TP + FP))."""
        denom = len(self.true_positives) + len(self.false_positives)
        return len(self.true_positives) / denom if denom else 1.0

    @property
    def recall(self) -> float:
        """Return recall metric (TP / (TP + FN))."""
        denom = len(self.true_positives) + len(self.false_negatives)
        return len(self.true_positives) / denom if denom else 1.0

    @property
    def f1(self) -> float:
        """Calculate F1 score (2 * precision * recall / (precision + recall))."""
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0


def discover_scenarios(repo_root: Path) -> list[ScenarioExpectation]:
    """Discover scenarios by loading every ``scenario.yaml`` under ``scenarios/``.

    Only scenarios that expose ``fixtures.mft``, ``fixtures.prefetch`` and
    ``fixtures.evtx`` (i.e. CSV-driven synthetic fixtures) are returned; disk
    image-based scenarios need a different runner.
    """
    scenarios_dir = repo_root / "scenarios"
    expectations: list[ScenarioExpectation] = []

    for manifest_path in sorted(scenarios_dir.glob("**/scenario.yaml")):
        # Skip schema reference file (scenarios/_schemas/scenario.yaml)
        if "_schemas" in manifest_path.parts:
            continue

        with manifest_path.open(encoding="utf-8") as handle:
            data = yaml.safe_load(handle) or {}

        fixtures = data.get("fixtures") or {}
        mft_fixture = fixtures.get("mft")
        prefetch_fixture = fixtures.get("prefetch")
        evtx_fixture = fixtures.get("evtx")
        browser_history_fixture = fixtures.get("browser_history")
        yara_rules_fixture = fixtures.get("yara_rules")
        yara_scan_dir_fixture = fixtures.get("yara_scan_dir")
        memory_fixtures_raw = fixtures.get("memory") or {}
        memory_fixtures = {
            str(key): str(value) for key, value in memory_fixtures_raw.items() if value
        }
        has_causality = bool(mft_fixture and prefetch_fixture and evtx_fixture)
        has_yara = bool(yara_rules_fixture and yara_scan_dir_fixture)
        has_memory = bool(memory_fixtures)
        if not has_causality and not has_yara and not has_memory:
            continue

        expected = data.get("expected") or {}
        malicious = expected.get("malicious_executables") or []
        finding_counts = expected.get("finding_counts") or {}
        fp_traps = expected.get("false_positive_traps") or []

        expectations.append(
            ScenarioExpectation(
                name=data.get("name") or manifest_path.parent.name,
                directory=manifest_path.parent,
                malicious_executables=frozenset(str(m).lower() for m in malicious),
                description=str(data.get("description") or "").strip(),
                mft_fixture=str(mft_fixture) if mft_fixture else "",
                prefetch_fixture=str(prefetch_fixture) if prefetch_fixture else "",
                evtx_fixture=str(evtx_fixture) if evtx_fixture else "",
                browser_history_fixture=(
                    str(browser_history_fixture) if browser_history_fixture else None
                ),
                shimcache_fixture=_optional_str(fixtures.get("shimcache")),
                amcache_fixture=_optional_str(fixtures.get("amcache")),
                bam_fixture=_optional_str(fixtures.get("bam")),
                userassist_fixture=_optional_str(fixtures.get("userassist")),
                run_keys_fixture=_optional_str(fixtures.get("run_keys")),
                yara_rules_fixture=_optional_str(yara_rules_fixture),
                yara_scan_dir_fixture=_optional_str(yara_scan_dir_fixture),
                memory_fixtures=memory_fixtures,
                finding_counts={k: int(v) for k, v in finding_counts.items()},
                false_positive_traps=frozenset(str(t).lower() for t in fp_traps),
            )
        )

    return expectations


def _optional_str(value: Any) -> Optional[str]:
    """Return ``str(value)`` if truthy, else ``None``."""
    return str(value) if value else None


def _run_registry_for_scenario(expectation: ScenarioExpectation) -> list[Finding]:
    """Run ``RegistryDetector`` on any registry fixtures declared by the scenario.

    Returns an empty list when no registry fixtures are present — scenarios
    that predate SFE-m9a stay untouched.
    """
    fixtures = {
        "shimcache": expectation.shimcache_fixture,
        "amcache": expectation.amcache_fixture,
        "bam": expectation.bam_fixture,
        "userassist": expectation.userassist_fixture,
        "run_keys": expectation.run_keys_fixture,
    }
    if not any(fixtures.values()):
        return []

    parser = RegistryParser()
    directory = expectation.directory
    kwargs: dict[str, Any] = {}

    if fixtures["shimcache"]:
        kwargs["shimcache"] = parser.parse_shimcache_csv(
            directory / fixtures["shimcache"]
        )
    if fixtures["amcache"]:
        kwargs["amcache"] = parser.parse_amcache_csv(directory / fixtures["amcache"])
    if fixtures["bam"]:
        kwargs["bam"] = parser.parse_bam_csv(directory / fixtures["bam"])
    if fixtures["userassist"]:
        kwargs["userassist"] = parser.parse_userassist_csv(
            directory / fixtures["userassist"]
        )
    if fixtures["run_keys"]:
        kwargs["run_keys"] = parser.parse_run_keys_csv(directory / fixtures["run_keys"])

    return RegistryDetector().analyze(**kwargs)


def _run_yara_for_scenario(expectation: ScenarioExpectation) -> list[Finding]:
    """Run YaraDetector on the scenario's yara_rules + yara_scan_dir fixtures.

    Returns ``[]`` when yara-python is missing or fixtures are incomplete,
    matching the scanner wrapper's graceful-degradation contract.
    """
    if not (
        _YARA_AVAILABLE
        and expectation.yara_rules_fixture
        and expectation.yara_scan_dir_fixture
    ):
        return []
    directory = expectation.directory
    rules_dir = directory / expectation.yara_rules_fixture
    scan_dir = directory / expectation.yara_scan_dir_fixture
    try:
        scanner = YaraScanner.compile_from_directory(rules_dir)
    except (MissingYaraError, ValueError, FileNotFoundError):
        return []
    return YaraDetector(scanner=scanner).analyze_directory(scan_dir)


_MEMORY_FIXTURE_COERCERS = {
    "windows_pslist": _to_process_row,
    "windows_psscan": _to_process_row,
    "windows_malfind": _to_injection_row,
    "windows_cmdline": _to_cmdline_row,
    "windows_netscan": _to_network_row,
    "linux_bash": _to_bash_history_row,
    "linux_pslist": _to_linux_process_row,
    "linux_sockstat": _to_linux_network_row,
}

_MEMORY_FIXTURE_TO_ANALYZE_KWARG = {
    "windows_pslist": "pslist",
    "windows_psscan": "psscan",
    "windows_malfind": "malfind",
    "windows_cmdline": "cmdline",
    "windows_netscan": "netscan",
    "linux_bash": "linux_bash",
    "linux_pslist": "linux_pslist",
    "linux_sockstat": "linux_sockstat",
}


def _run_memory_for_scenario(expectation: ScenarioExpectation) -> list[Finding]:
    """Run MemoryDetector on the scenario's pre-parsed Volatility JSON fixtures.

    Each fixture file contains the raw row list Volatility 3's ``-r json``
    renderer produces for one plugin. We coerce them into the runner's
    typed dataclasses via the same ``_to_*_row`` helpers the live runner
    uses, so a shape change in Volatility surfaces in one place.
    """
    if not expectation.memory_fixtures:
        return []
    directory = expectation.directory
    analyze_kwargs: dict[str, Any] = {}
    for plugin_key, fixture_rel in expectation.memory_fixtures.items():
        coercer = _MEMORY_FIXTURE_COERCERS.get(plugin_key)
        analyze_key = _MEMORY_FIXTURE_TO_ANALYZE_KWARG.get(plugin_key)
        if coercer is None or analyze_key is None:
            continue
        fixture_path = directory / fixture_rel
        if not fixture_path.is_file():
            continue
        with fixture_path.open(encoding="utf-8") as handle:
            raw_rows = json.load(handle)
        if not isinstance(raw_rows, list):
            continue
        analyze_kwargs[analyze_key] = [coercer(row) for row in raw_rows]
    if not analyze_kwargs:
        return []
    return MemoryDetector().analyze(**analyze_kwargs)


def _scenario_raw_evidence(directory: Path) -> str:
    """Concatenate the scenario's fixture text as the raw evidence blob.

    Reads the CSV/JSON fixtures the detectors consumed so the adversarial pass can
    re-derive asserted anchors (IP/PID) against real evidence rather than a
    finding's own narrative. Best-effort: unreadable/binary files are skipped.
    """
    parts: list[str] = []
    for path in sorted(directory.rglob("*")):
        if path.is_file() and path.suffix.lower() in {".csv", ".json"}:
            try:
                parts.append(path.read_text(encoding="utf-8", errors="ignore"))
            except OSError:
                continue
    return "\n".join(parts)


def run_scenario(expectation: ScenarioExpectation) -> ScenarioResult:
    """Execute the engine for one scenario and compare to ground truth.

    Runs SelfCorrectionEngine (when mft/prefetch/evtx are declared), the
    NetworkDetector (when browser history is provided), and YaraDetector
    (when yara_rules + yara_scan_dir are provided). Findings from every
    pipeline feed into the same precision/recall accounting.
    """
    directory = expectation.directory
    has_causality = bool(
        expectation.mft_fixture
        and expectation.prefetch_fixture
        and expectation.evtx_fixture
    )

    findings: list[Finding] = []
    mft: list = []

    lateral_findings: list = []
    if has_causality:
        mft = MFTParser().parse_csv(directory / expectation.mft_fixture)
        prefetch = PrefetchParser().parse_csv(directory / expectation.prefetch_fixture)
        evtx = EventLogParser().parse_csv(
            directory / expectation.evtx_fixture, filter_event_ids=[4688]
        )
        findings.extend(SelfCorrectionEngine().analyze(mft, prefetch, evtx))
        findings.extend(_run_registry_for_scenario(expectation))

        # Lateral-movement runs over the authentication events (4624/4625/4648),
        # which are disjoint from the 4688 process-creation events the causality
        # engine consumes. Re-parse without the 4688 filter so logon rows survive.
        auth_events = EventLogParser().parse_csv(directory / expectation.evtx_fixture)
        lateral_findings = LateralMovementDetector().analyze(auth_events)
        findings.extend(lateral_findings)

    network_findings: list = []
    if expectation.browser_history_fixture:
        browser_history = BrowserHistoryParser().parse_csv(
            directory / expectation.browser_history_fixture
        )
        mft_records = [
            MFTAccessRecord(
                filename=entry.file_name,
                parent_path=entry.parent_path,
                accessed=entry.si_accessed or entry.fn_accessed,
            )
            for entry in mft
            if (entry.si_accessed or entry.fn_accessed) is not None
        ]
        network_findings = NetworkDetector().analyze(
            browser_history=browser_history,
            mft_records=mft_records,
        )
        findings.extend(network_findings)

    yara_findings = _run_yara_for_scenario(expectation)
    findings.extend(yara_findings)

    memory_findings = _run_memory_for_scenario(expectation)
    findings.extend(memory_findings)

    detected = [f.evidence.get("executable", "").lower() for f in findings]
    expected = set(expectation.malicious_executables)

    tp = [name for name in detected if name and name in expected]
    fp = [name for name in detected if name and name not in expected]
    fn = [name for name in expected if name not in detected]

    # When the scenario's expected finding is a category count rather than a
    # named executable (webmail exfiltration, cloud-storage upload), match
    # on the structured exfil_type evidence field instead of title substring.
    webmail_expected = expectation.finding_counts.get("webmail_exfiltration", 0)
    if webmail_expected:
        matched = [
            f
            for f in network_findings
            if f.category.value == "data_exfiltration"
            and f.evidence.get("exfil_type") == "webmail"
        ]
        tp.extend(["webmail_exfiltration"] * min(webmail_expected, len(matched)))
        missing = max(webmail_expected - len(matched), 0)
        fn.extend(["webmail_exfiltration"] * missing)

    cloud_expected = expectation.finding_counts.get("cloud_upload", 0)
    if cloud_expected:
        matched = [
            f
            for f in network_findings
            if f.category.value == "data_exfiltration"
            and f.evidence.get("exfil_type") == "cloud_upload"
        ]
        tp.extend(["cloud_upload"] * min(cloud_expected, len(matched)))
        missing = max(cloud_expected - len(matched), 0)
        fn.extend(["cloud_upload"] * missing)

    yara_expected = expectation.finding_counts.get("yara_match", 0)
    if yara_expected:
        matched = [
            f for f in yara_findings if f.category.value == "malware_classification"
        ]
        tp.extend(["yara_match"] * min(yara_expected, len(matched)))
        missing = max(yara_expected - len(matched), 0)
        fn.extend(["yara_match"] * missing)

    lateral_expected = expectation.finding_counts.get("lateral_movement", 0)
    if lateral_expected:
        matched = [
            f for f in lateral_findings if f.category.value == "lateral_movement"
        ]
        tp.extend(["lateral_movement"] * min(lateral_expected, len(matched)))
        missing = max(lateral_expected - len(matched), 0)
        fn.extend(["lateral_movement"] * missing)
        extra = max(len(matched) - lateral_expected, 0)
        fp.extend(["lateral_movement"] * extra)

    memory_expected = expectation.finding_counts.get("memory_finding", 0)
    if memory_expected:
        matched_count = len(memory_findings)
        tp.extend(["memory_finding"] * min(memory_expected, matched_count))
        missing = max(memory_expected - matched_count, 0)
        fn.extend(["memory_finding"] * missing)
        extra = max(matched_count - memory_expected, 0)
        fp.extend(["memory_finding"] * extra)

    avg_conf = sum(f.confidence for f in findings) / len(findings) if findings else 0.0

    # Execution-path convergence: harden this scenario's findings through the
    # SAME pipeline the orchestrator uses, so the recall path carries receipts,
    # verdict clamps, and tool-semantics checks. Additive only - `findings` and
    # the tp/fp/fn accounting above are untouched, so F1 is unaffected. The
    # per-scenario image hash + fixed key make the receipts deterministic for a
    # given fixture set (reproducible across harness runs).
    image_sha256 = hashlib.sha256(
        str(expectation.directory.name).encode("utf-8")
    ).hexdigest()
    # Raw evidence for INDEPENDENT anchor re-derivation: the concatenated text of
    # the scenario's own fixture files (the bytes the detectors consumed). The
    # adversarial falsifier re-derives a finding's asserted IP/PID against THIS,
    # not the finding's narrative - so a hallucinated anchor is killed even if the
    # finding's own reasoning cites it. Every finding maps to the same evidence
    # blob (a per-finding split would need detector-level provenance we don't yet
    # emit; the blob is still genuinely independent of any single finding's prose).
    raw_evidence = _scenario_raw_evidence(expectation.directory)
    evidence_texts = {f.title: raw_evidence for f in findings}
    hardening = harden_findings(
        findings,
        image_sha256=image_sha256,
        receipt_key=b"scenario-harness-hardening-key-32",
        tool="scenario_harness",
        evidence_texts=evidence_texts,
    )

    return ScenarioResult(
        name=expectation.name,
        findings_count=len(findings),
        detected_executables=detected,
        true_positives=tp,
        false_positives=fp,
        false_negatives=fn,
        average_confidence=avg_conf,
        hardening=hardening,
    )


def aggregate(results: list[ScenarioResult]) -> dict[str, Any]:
    """Compute micro-averaged precision/recall/F1 across all scenarios."""
    tp = sum(len(r.true_positives) for r in results)
    fp = sum(len(r.false_positives) for r in results)
    fn = sum(len(r.false_negatives) for r in results)

    precision = tp / (tp + fp) if (tp + fp) else 1.0
    recall = tp / (tp + fn) if (tp + fn) else 1.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0

    return {
        "true_positives": tp,
        "false_positives": fp,
        "false_negatives": fn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
    }


def main() -> None:
    """Run all scenarios and print aggregated metrics."""
    repo_root = Path(__file__).resolve().parent.parent
    scenarios = discover_scenarios(repo_root)
    results = [run_scenario(s) for s in scenarios]

    print(
        f"\n{'Scenario':<26}{'TP':>4}{'FP':>4}{'FN':>4}"
        f"{'Prec':>8}{'Rec':>8}{'F1':>8}{'AvgConf':>10}"
    )
    print("-" * 82)
    for r in results:
        print(
            f"{r.name:<26}"
            f"{len(r.true_positives):>4}"
            f"{len(r.false_positives):>4}"
            f"{len(r.false_negatives):>4}"
            f"{r.precision:>8.2f}{r.recall:>8.2f}{r.f1:>8.2f}{r.average_confidence:>10.2f}"
        )

    agg = aggregate(results)
    print("-" * 82)
    print(
        f"{'TOTAL':<26}{agg['true_positives']:>4}{agg['false_positives']:>4}"
        f"{agg['false_negatives']:>4}{agg['precision']:>8.2f}"
        f"{agg['recall']:>8.2f}{agg['f1']:>8.2f}"
    )

    report_path = repo_root / "analysis" / "scenario_report.json"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    with report_path.open("w", encoding="utf-8") as handle:
        json.dump(
            {
                "scenarios": [
                    {
                        "name": r.name,
                        "findings_count": r.findings_count,
                        "detected": r.detected_executables,
                        "true_positives": r.true_positives,
                        "false_positives": r.false_positives,
                        "false_negatives": r.false_negatives,
                        "precision": r.precision,
                        "recall": r.recall,
                        "f1": r.f1,
                        "average_confidence": r.average_confidence,
                    }
                    for r in results
                ],
                "aggregate": agg,
            },
            handle,
            indent=2,
        )

    print(f"\nReport written to {report_path}")


if __name__ == "__main__":
    main()
