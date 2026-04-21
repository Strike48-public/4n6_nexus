"""Run all scenarios and compute precision / recall / F1 metrics.

Scenarios are discovered automatically from ``scenarios/**/scenario.yaml``
manifests that declare ``fixtures.mft``, ``fixtures.prefetch``, and
``fixtures.evtx`` inputs. Manifests without those fixtures (for example E01
or PCAP scenarios in ``real/`` and ``training/``) are skipped here because
they require disk-level parsing outside this harness.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import yaml

from sift_find_evil.detectors import NetworkDetector
from sift_find_evil.detectors.registry_detector import RegistryDetector
from sift_find_evil.detectors.webmail_exfil_detector import MFTAccessRecord
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
    finding_counts: dict[str, int] = field(default_factory=dict)


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
        has_causality = bool(mft_fixture and prefetch_fixture and evtx_fixture)
        has_yara = bool(yara_rules_fixture and yara_scan_dir_fixture)
        if not has_causality and not has_yara:
            continue

        expected = data.get("expected") or {}
        malicious = expected.get("malicious_executables") or []
        finding_counts = expected.get("finding_counts") or {}

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
                finding_counts={k: int(v) for k, v in finding_counts.items()},
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
        kwargs["amcache"] = parser.parse_amcache_csv(
            directory / fixtures["amcache"]
        )
    if fixtures["bam"]:
        kwargs["bam"] = parser.parse_bam_csv(directory / fixtures["bam"])
    if fixtures["userassist"]:
        kwargs["userassist"] = parser.parse_userassist_csv(
            directory / fixtures["userassist"]
        )
    if fixtures["run_keys"]:
        kwargs["run_keys"] = parser.parse_run_keys_csv(
            directory / fixtures["run_keys"]
        )

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

    if has_causality:
        mft = MFTParser().parse_csv(directory / expectation.mft_fixture)
        prefetch = PrefetchParser().parse_csv(
            directory / expectation.prefetch_fixture
        )
        evtx = EventLogParser().parse_csv(
            directory / expectation.evtx_fixture, filter_event_ids=[4688]
        )
        findings.extend(SelfCorrectionEngine().analyze(mft, prefetch, evtx))
        findings.extend(_run_registry_for_scenario(expectation))

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

    detected = [f.evidence.get("executable", "").lower() for f in findings]
    expected = set(expectation.malicious_executables)

    tp = [name for name in detected if name and name in expected]
    fp = [name for name in detected if name and name not in expected]
    fn = [name for name in expected if name not in detected]

    # When the scenario's expected finding is a category count rather than a
    # named executable (webmail exfiltration, cloud-storage upload), count
    # each title-matching finding as a true positive up to the expected total.
    webmail_expected = expectation.finding_counts.get("webmail_exfiltration", 0)
    if webmail_expected:
        matched = [
            f for f in network_findings
            if f.category.value == "data_exfiltration"
            and "webmail" in f.title.lower()
        ]
        tp.extend(["webmail_exfiltration"] * min(webmail_expected, len(matched)))
        missing = max(webmail_expected - len(matched), 0)
        fn.extend(["webmail_exfiltration"] * missing)

    cloud_expected = expectation.finding_counts.get("cloud_upload", 0)
    if cloud_expected:
        matched = [
            f for f in network_findings
            if f.category.value == "data_exfiltration"
            and "cloud-storage" in f.title.lower()
        ]
        tp.extend(["cloud_upload"] * min(cloud_expected, len(matched)))
        missing = max(cloud_expected - len(matched), 0)
        fn.extend(["cloud_upload"] * missing)

    yara_expected = expectation.finding_counts.get("yara_match", 0)
    if yara_expected:
        matched = [
            f for f in yara_findings
            if f.category.value == "malware_classification"
        ]
        tp.extend(["yara_match"] * min(yara_expected, len(matched)))
        missing = max(yara_expected - len(matched), 0)
        fn.extend(["yara_match"] * missing)

    avg_conf = (
        sum(f.confidence for f in findings) / len(findings) if findings else 0.0
    )

    return ScenarioResult(
        name=expectation.name,
        findings_count=len(findings),
        detected_executables=detected,
        true_positives=tp,
        false_positives=fp,
        false_negatives=fn,
        average_confidence=avg_conf,
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
