"""Run a scenario end-to-end from its scenario.yaml manifest.

A scenario.yaml declares either ``fixtures`` (tracked CSVs for synthetic
tiers) or ``evidence`` (binary artifacts for real / training tiers). The
runner loads the manifest, dispatches to the right parsers/detectors based
on what is declared and present on disk, and compares the resulting
findings against ``expected:`` ground truth.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .detectors import NetworkDetector, RegistryDetector
from .detectors.webmail_exfil_detector import MFTAccessRecord
from .disk.wipe_detector import detect_from_image
from .parsers.browser_history_parser import BrowserHistoryParser
from .parsers.evtx_parser import EventLogParser
from .parsers.mft_parser import MFTParser
from .parsers.prefetch_parser import PrefetchParser
from .parsers.registry_parser import RegistryParser
from .self_correction.engine import SelfCorrectionEngine

# yara-python is optional; detector import is deferred so scenarios without
# YARA fixtures still work on hosts that do not have libyara installed.
try:
    from .detectors.yara_detector import YaraDetector
    from .yara_scan.scanner import MissingYaraError, YaraScanner
    _YARA_AVAILABLE = True
except ImportError:  # pragma: no cover — only exercised on hosts without libyara
    YaraDetector = None  # type: ignore[assignment]
    YaraScanner = None  # type: ignore[assignment]
    MissingYaraError = RuntimeError  # type: ignore[assignment,misc]
    _YARA_AVAILABLE = False


MAX_MANIFEST_SIZE = 1_048_576  # 1 MiB cap guards against YAML bombs on memory-limited DFIR workstations.


class ScenarioLoadError(ValueError):
    """Raised when a scenario manifest is missing or malformed."""


def _resolve_inside(directory: Path, relative: str) -> Path:
    """Resolve ``relative`` under ``directory`` and reject path-traversal escapes."""
    candidate = (directory / relative).resolve()
    base = directory.resolve()
    if not candidate.is_relative_to(base):
        raise ScenarioLoadError(
            f"path escapes scenario directory: {relative!r}"
        )
    return candidate


@dataclass(frozen=True)
class ScenarioManifest:
    """Parsed scenario.yaml manifest."""

    name: str
    tier: str
    directory: Path
    description: str
    fixtures: dict[str, str]
    evidence: list[dict[str, Any]]
    expected_malicious_executables: frozenset[str]
    expected_finding_counts: dict[str, int]
    min_precision: float
    min_recall: float


@dataclass
class ScenarioReport:
    """Outcome of running one scenario against its expectations."""

    manifest: ScenarioManifest
    findings_count: int
    detected_executables: list[str]
    true_positives: list[str] = field(default_factory=list)
    false_positives: list[str] = field(default_factory=list)
    false_negatives: list[str] = field(default_factory=list)
    average_confidence: float = 0.0
    skipped: bool = False
    skip_reason: str = ""

    @property
    def precision(self) -> float:
        """TP / (TP + FP). Returns 1.0 only when detector produced zero output and none was expected.

        For a no-detection / no-expectation scenario (tp=fp=fn=0) both precision
        and recall are 1.0 by convention. A manifest that expects findings but
        gets none will produce tp=fp=0, fn>0, giving precision=1.0 and recall<1.0,
        so recall is the load-bearing gate for detection completeness. Always
        set `min_recall` alongside `min_precision` in manifest expectations.
        """
        denom = len(self.true_positives) + len(self.false_positives)
        return len(self.true_positives) / denom if denom else 1.0

    @property
    def recall(self) -> float:
        """TP / (TP + FN). Returns 1.0 only when no findings were expected."""
        denom = len(self.true_positives) + len(self.false_negatives)
        return len(self.true_positives) / denom if denom else 1.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    @property
    def passed(self) -> bool:
        """A scenario passes when precision/recall meet the manifest minimums.

        Skipped scenarios pass vacuously; callers that need strict CI gating
        should inspect ``report.skipped`` directly (see ``cmd_run``'s
        ``--strict`` flag).
        """
        if self.skipped:
            return True
        return (
            self.precision >= self.manifest.min_precision
            and self.recall >= self.manifest.min_recall
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.manifest.name,
            "tier": self.manifest.tier,
            "directory": str(self.manifest.directory),
            "passed": self.passed,
            "skipped": self.skipped,
            "skip_reason": self.skip_reason,
            "findings_count": self.findings_count,
            "detected_executables": self.detected_executables,
            "true_positives": self.true_positives,
            "false_positives": self.false_positives,
            "false_negatives": self.false_negatives,
            "precision": self.precision,
            "recall": self.recall,
            "f1": self.f1,
            "average_confidence": self.average_confidence,
        }


def load_scenario(path: Path) -> ScenarioManifest:
    """Load a scenario manifest from a directory or a scenario.yaml path.

    Enforces a 1 MiB manifest size cap, rejects path-traversal in fixture
    and evidence paths, and validates expected-block field types so that
    misconfigured manifests fail loudly at load time instead of producing
    silent false-negatives during scoring.
    """
    manifest_path = path / "scenario.yaml" if path.is_dir() else path
    if not manifest_path.is_file():
        raise ScenarioLoadError(f"scenario.yaml not found at {manifest_path}")

    size = manifest_path.stat().st_size
    if size > MAX_MANIFEST_SIZE:
        raise ScenarioLoadError(
            f"{manifest_path}: manifest is {size} bytes (max {MAX_MANIFEST_SIZE})"
        )

    with manifest_path.open(encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}

    if not isinstance(data, dict):
        raise ScenarioLoadError(f"{manifest_path}: top-level must be a mapping")

    directory = manifest_path.parent
    name = data.get("name") or directory.name
    tier = data.get("tier") or "unknown"

    fixtures_raw = data.get("fixtures") or {}
    if not isinstance(fixtures_raw, dict):
        raise ScenarioLoadError(f"{manifest_path}: 'fixtures' must be a mapping")
    fixtures: dict[str, str] = {}
    for key, val in fixtures_raw.items():
        if not val:
            continue
        if not isinstance(val, str):
            raise ScenarioLoadError(
                f"{manifest_path}: fixtures.{key} must be a string path, got {type(val).__name__}"
            )
        _resolve_inside(directory, val)
        fixtures[str(key)] = val

    evidence_raw = data.get("evidence") or []
    if not isinstance(evidence_raw, list):
        raise ScenarioLoadError(f"{manifest_path}: 'evidence' must be a list")
    evidence: list[dict[str, Any]] = []
    for entry in evidence_raw:
        if not isinstance(entry, dict):
            continue
        entry_path = entry.get("path")
        if not isinstance(entry_path, str) or not entry_path:
            raise ScenarioLoadError(
                f"{manifest_path}: evidence entry missing string 'path'"
            )
        _resolve_inside(directory, entry_path)
        evidence.append(dict(entry))

    expected = data.get("expected") or {}
    malicious = expected.get("malicious_executables") or []
    if not isinstance(malicious, list) or not all(isinstance(m, str) for m in malicious):
        raise ScenarioLoadError(
            f"{manifest_path}: expected.malicious_executables must be a list of strings"
        )
    finding_counts = expected.get("finding_counts") or {}
    if not isinstance(finding_counts, dict):
        raise ScenarioLoadError(
            f"{manifest_path}: expected.finding_counts must be a mapping"
        )
    try:
        finding_counts_int = {str(k): int(v) for k, v in finding_counts.items()}
    except (TypeError, ValueError) as exc:
        raise ScenarioLoadError(
            f"{manifest_path}: expected.finding_counts values must be integers ({exc})"
        ) from exc
    try:
        min_precision = float(expected.get("min_precision", 1.0))
        min_recall = float(expected.get("min_recall", 1.0))
    except (TypeError, ValueError) as exc:
        raise ScenarioLoadError(
            f"{manifest_path}: expected.min_precision/min_recall must be numeric ({exc})"
        ) from exc

    return ScenarioManifest(
        name=str(name),
        tier=str(tier),
        directory=directory,
        description=str(data.get("description") or "").strip(),
        fixtures=fixtures,
        evidence=evidence,
        expected_malicious_executables=frozenset(m.lower() for m in malicious),
        expected_finding_counts=finding_counts_int,
        min_precision=min_precision,
        min_recall=min_recall,
    )


def run_scenario_path(path: Path) -> ScenarioReport:
    """Load and execute one scenario, returning its report."""
    manifest = load_scenario(path)
    return run_scenario(manifest)


def run_scenario(manifest: ScenarioManifest) -> ScenarioReport:
    """Dispatch parsers/detectors according to what the manifest declares."""
    if manifest.fixtures:
        return _run_fixture_scenario(manifest)
    if manifest.evidence:
        return _run_evidence_scenario(manifest)
    return _skip(manifest, "manifest declares neither fixtures nor evidence")


def _run_fixture_scenario(manifest: ScenarioManifest) -> ScenarioReport:
    directory = manifest.directory
    fixtures = manifest.fixtures

    mft_name = fixtures.get("mft")
    prefetch_name = fixtures.get("prefetch")
    evtx_name = fixtures.get("evtx")
    yara_rules_name = fixtures.get("yara_rules")
    yara_scan_dir_name = fixtures.get("yara_scan_dir")
    has_causality = bool(mft_name and prefetch_name and evtx_name)
    has_yara = bool(yara_rules_name and yara_scan_dir_name)

    # A scenario is YARA-only when it declares yara_rules + yara_scan_dir and
    # omits the causality triplet. That lets SFE-86p ship scenarios that
    # exercise malware classification without manufacturing synthetic MFT,
    # prefetch, and event log CSVs just to pass the required-fixture gate.
    if not has_causality and not has_yara:
        return _skip(manifest, "fixture scenario missing required mft/prefetch/evtx")

    findings: list = []
    mft: list = []

    if has_causality:
        mft = MFTParser().parse_csv(directory / mft_name)
        prefetch = PrefetchParser().parse_csv(directory / prefetch_name)
        evtx = EventLogParser().parse_csv(
            directory / evtx_name, filter_event_ids=[4688]
        )
        findings.extend(SelfCorrectionEngine().analyze(mft, prefetch, evtx))
        findings.extend(_run_registry(manifest))

    network_findings: list = []
    browser_history_name = fixtures.get("browser_history")
    if browser_history_name:
        browser_history = BrowserHistoryParser().parse_csv(
            directory / browser_history_name
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

    yara_findings: list = []
    if has_yara:
        yara_findings = _run_yara(manifest)
        findings.extend(yara_findings)

    return _score(manifest, findings, network_findings, yara_findings)


def _run_registry(manifest: ScenarioManifest) -> list:
    fixtures = manifest.fixtures
    paths = {
        "shimcache": fixtures.get("shimcache"),
        "amcache": fixtures.get("amcache"),
        "bam": fixtures.get("bam"),
        "userassist": fixtures.get("userassist"),
        "run_keys": fixtures.get("run_keys"),
    }
    if not any(paths.values()):
        return []

    parser = RegistryParser()
    directory = manifest.directory
    kwargs: dict[str, Any] = {}
    if paths["shimcache"]:
        kwargs["shimcache"] = parser.parse_shimcache_csv(
            directory / paths["shimcache"]
        )
    if paths["amcache"]:
        kwargs["amcache"] = parser.parse_amcache_csv(directory / paths["amcache"])
    if paths["bam"]:
        kwargs["bam"] = parser.parse_bam_csv(directory / paths["bam"])
    if paths["userassist"]:
        kwargs["userassist"] = parser.parse_userassist_csv(
            directory / paths["userassist"]
        )
    if paths["run_keys"]:
        kwargs["run_keys"] = parser.parse_run_keys_csv(
            directory / paths["run_keys"]
        )

    return RegistryDetector().analyze(**kwargs)


def _run_yara(manifest: ScenarioManifest) -> list:
    """Compile the scenario's YARA rules and scan its sample directory.

    Returns ``[]`` when yara-python is not installed; the scenario is expected
    to either skip gracefully elsewhere or carry non-YARA expectations that
    still pass. YARA-only scenarios surface the missing dependency at the
    manifest-expects-but-nothing-found layer so CI gates catch the regression.
    """
    if not _YARA_AVAILABLE:
        return []

    fixtures = manifest.fixtures
    rules_dir_name = fixtures["yara_rules"]
    scan_dir_name = fixtures["yara_scan_dir"]
    rules_dir = manifest.directory / rules_dir_name
    scan_dir = manifest.directory / scan_dir_name

    try:
        scanner = YaraScanner.compile_from_directory(rules_dir)
    except (MissingYaraError, ValueError, FileNotFoundError):
        return []
    detector = YaraDetector(scanner=scanner)
    return detector.analyze_directory(scan_dir)


def _run_evidence_scenario(manifest: ScenarioManifest) -> ScenarioReport:
    directory = manifest.directory
    present = [
        entry
        for entry in manifest.evidence
        if (directory / str(entry.get("path", ""))).is_file()
    ]
    required = [
        entry
        for entry in manifest.evidence
        if entry.get("required")
    ]
    required_present = [
        entry
        for entry in required
        if (directory / str(entry.get("path", ""))).is_file()
    ]

    if required and len(required_present) < len(required):
        missing = [
            str(entry.get("path"))
            for entry in required
            if (directory / str(entry.get("path", ""))).is_file() is False
        ]
        return _skip(
            manifest,
            f"missing required evidence on disk: {', '.join(missing)}",
        )
    if not present:
        return _skip(manifest, "no evidence files present on disk")

    findings: list = []
    dispatched_kinds: set[str] = set()
    for entry in present:
        kind = str(entry.get("kind") or "").lower()
        evidence_path = directory / str(entry["path"])
        if kind == "e01" or kind == "dd" or kind == "raw":
            wipe = detect_from_image(evidence_path)
            if wipe is not None:
                findings.append(wipe)
            dispatched_kinds.add(kind)
        # PCAP and other binary kinds have no single-file detector here yet;
        # they are orchestrated through `analyze` with --pcap. File follow-up
        # tickets cover full dispatch (bd SFE-45q for cloud upload, etc.).

    if not dispatched_kinds:
        return _skip(
            manifest,
            "evidence present but no dispatchable kind (e01/dd/raw) found",
        )

    return _score(manifest, findings, network_findings=[], yara_findings=[])


def _score(
    manifest: ScenarioManifest,
    findings: list,
    network_findings: list,
    yara_findings: list,
) -> ScenarioReport:
    detected = [f.evidence.get("executable", "").lower() for f in findings]
    expected = set(manifest.expected_malicious_executables)

    tp = [name for name in detected if name and name in expected]
    fp = [name for name in detected if name and name not in expected]
    fn = [name for name in expected if name not in detected]

    webmail_expected = manifest.expected_finding_counts.get("webmail_exfiltration", 0)
    if webmail_expected:
        matched = [
            f for f in network_findings
            if f.category.value == "data_exfiltration"
            and f.evidence.get("exfil_type") == "webmail"
        ]
        tp.extend(["webmail_exfiltration"] * min(webmail_expected, len(matched)))
        missing = max(webmail_expected - len(matched), 0)
        fn.extend(["webmail_exfiltration"] * missing)

    cloud_expected = manifest.expected_finding_counts.get("cloud_upload", 0)
    if cloud_expected:
        matched = [
            f for f in network_findings
            if f.category.value == "data_exfiltration"
            and f.evidence.get("exfil_type") == "cloud_upload"
        ]
        tp.extend(["cloud_upload"] * min(cloud_expected, len(matched)))
        missing = max(cloud_expected - len(matched), 0)
        fn.extend(["cloud_upload"] * missing)

    yara_expected = manifest.expected_finding_counts.get("yara_match", 0)
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

    return ScenarioReport(
        manifest=manifest,
        findings_count=len(findings),
        detected_executables=detected,
        true_positives=tp,
        false_positives=fp,
        false_negatives=fn,
        average_confidence=avg_conf,
    )


def _skip(manifest: ScenarioManifest, reason: str) -> ScenarioReport:
    return ScenarioReport(
        manifest=manifest,
        findings_count=0,
        detected_executables=[],
        skipped=True,
        skip_reason=reason,
    )


__all__ = [
    "ScenarioLoadError",
    "ScenarioManifest",
    "ScenarioReport",
    "load_scenario",
    "run_scenario",
    "run_scenario_path",
]
