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

from sift_find_evil.correlation.hidden_process import detect_hidden_linux_processes
from sift_find_evil.hardening import HardeningReport, harden_findings
from sift_find_evil.injection_defense import finding_from_scan, scan_and_wrap
from sift_find_evil.detectors import NetworkDetector
from sift_find_evil.detectors.memory_detector import MemoryDetector
from sift_find_evil.detectors.registry_detector import RegistryDetector
from sift_find_evil.detectors.sigma_scan.evtx_adapter import event_to_sigma
from sift_find_evil.detectors.sigma_scan.loader import load_sigma_corpus
from sift_find_evil.detectors.sigma_scan.matcher import match_events
from sift_find_evil.detectors.webmail_exfil_detector import MFTAccessRecord
from sift_find_evil.memory.analysis import PLUGIN_COERCERS, coerce_streams
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

# Repository root, used to locate committed config-as-data (e.g. the pinned
# Sigma corpus under rules/sigma). Scenario discovery still takes an explicit
# repo_root argument; this is only for corpora that live at a fixed path.
_REPO_ROOT = Path(__file__).resolve().parent.parent


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
    injection_fixture: Optional[str] = None
    linux_artifacts_fixture: Optional[str] = None
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
    # The raw Finding objects this scenario produced, in emission order. Exposed
    # for tests/consumers that assert on finding shape (category, evidence keys)
    # rather than the tp/fp/fn accounting. Additive; does not affect scoring.
    findings: list[Finding] = field(default_factory=list)

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

        # Skip the held-out benchmark corpus (scenarios/heldout/*). It is scored
        # ONLY by the blind hallucination benchmark (benchmark/heldout.py), never
        # by the F1 recall harness - the two corpora must stay disjoint so a
        # held-out case can neither inflate F1 nor be inflated by it (SFE-i7l7).
        if "heldout" in manifest_path.parts:
            continue

        expectation = expectation_from_manifest(manifest_path)
        if expectation is not None:
            expectations.append(expectation)

    return expectations


def expectation_from_manifest(manifest_path: Path) -> Optional[ScenarioExpectation]:
    """Parse one ``scenario.yaml`` into a ScenarioExpectation, or None if it is not
    a CSV/fixture-driven scenario this harness can run.

    Extracted so the held-out benchmark corpus (``scenarios/heldout/``), which
    ``discover_scenarios`` deliberately skips, can be parsed by the SAME loader
    without duplicating the fixture schema (SFE-i7l7). Returns None for a manifest
    with no causality/yara/memory/injection fixtures (e.g. a PCAP/E01 scenario).
    """
    with manifest_path.open(encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}

    fixtures = data.get("fixtures") or {}
    mft_fixture = fixtures.get("mft")
    prefetch_fixture = fixtures.get("prefetch")
    evtx_fixture = fixtures.get("evtx")
    browser_history_fixture = fixtures.get("browser_history")
    yara_rules_fixture = fixtures.get("yara_rules")
    yara_scan_dir_fixture = fixtures.get("yara_scan_dir")
    injection_fixture = fixtures.get("injection")
    linux_artifacts_fixture = fixtures.get("linux_artifacts")
    memory_fixtures_raw = fixtures.get("memory") or {}
    memory_fixtures = {
        str(key): str(value) for key, value in memory_fixtures_raw.items() if value
    }
    has_causality = bool(mft_fixture and prefetch_fixture and evtx_fixture)
    has_yara = bool(yara_rules_fixture and yara_scan_dir_fixture)
    has_memory = bool(memory_fixtures)
    has_injection = bool(injection_fixture)
    has_linux = bool(linux_artifacts_fixture)
    if (
        not has_causality
        and not has_yara
        and not has_memory
        and not has_injection
        and not has_linux
    ):
        return None

    expected = data.get("expected") or {}
    malicious = expected.get("malicious_executables") or []
    finding_counts = expected.get("finding_counts") or {}
    fp_traps = expected.get("false_positive_traps") or []

    return ScenarioExpectation(
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
        injection_fixture=_optional_str(injection_fixture),
        linux_artifacts_fixture=_optional_str(linux_artifacts_fixture),
        memory_fixtures=memory_fixtures,
        finding_counts={k: int(v) for k, v in finding_counts.items()},
        false_positive_traps=frozenset(str(t).lower() for t in fp_traps),
    )


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


def _run_memory_for_scenario(expectation: ScenarioExpectation) -> list[Finding]:
    """Run MemoryDetector on the scenario's pre-parsed Volatility JSON fixtures.

    Each fixture file contains the raw row list Volatility 3's ``-r json``
    renderer produces for one plugin. Coercion into the runner's typed
    dataclasses is delegated to :func:`sift_find_evil.memory.analysis.coerce_streams`
    — the SAME coercer map the connector adapter uses — so a Volatility shape
    change surfaces in exactly one place. Only the coercers are shared, not path
    resolution: unlike the connector's ``analyze_memory_dir`` (which globs
    ``<plugin_key>.json`` in a directory), the harness honors the per-plugin
    relative paths declared in each ``scenario.yaml``.
    """
    if not expectation.memory_fixtures:
        return []
    directory = expectation.directory
    raw_by_plugin: dict[str, list] = {}
    for plugin_key, fixture_rel in expectation.memory_fixtures.items():
        if plugin_key not in PLUGIN_COERCERS:
            continue
        fixture_path = directory / fixture_rel
        if not fixture_path.is_file():
            continue
        with fixture_path.open(encoding="utf-8") as handle:
            raw_rows = json.load(handle)
        if not isinstance(raw_rows, list):
            continue
        raw_by_plugin[plugin_key] = raw_rows
    analyze_kwargs = coerce_streams(raw_by_plugin)
    if not analyze_kwargs:
        return []
    return MemoryDetector().analyze(**analyze_kwargs)


def _run_sigma_for_scenario(expectation: ScenarioExpectation) -> list[Finding]:
    """Run the pinned Sigma corpus over the scenario's EVTX events.

    Parses the scenario's EVTX fixture, flattens each entry to a Sigma event
    (:func:`event_to_sigma`), and evaluates the committed ``rules/sigma`` corpus.
    Returns ``[]`` when no EVTX fixture is declared or the corpus is empty, so
    Sigma is opportunistic and never required. Findings carry no ``executable``
    key, so they never enter the named-executable tp/fp/fn accounting; they are
    scored only via the opt-in ``sigma_match`` finding_counts category.
    """
    if not expectation.evtx_fixture:
        return []
    fixture_path = expectation.directory / expectation.evtx_fixture
    if not fixture_path.is_file():
        return []
    rules = load_sigma_corpus(_REPO_ROOT / "rules" / "sigma")
    if not rules:
        return []
    events = [
        event_to_sigma(entry) for entry in EventLogParser().parse_csv(fixture_path)
    ]
    return match_events(rules, events)


def _run_injection_for_scenario(expectation: ScenarioExpectation) -> list[Finding]:
    """Scan the scenario's injection fixture and emit a finding if it is hostile.

    Evidence text can carry adversarial content crafted to manipulate an
    automated analyst. ``scan_and_wrap`` sanitizes + sentinel-wraps it and
    ``finding_from_scan`` promotes any detected attempt to a scoreable
    ANTI_FORENSICS finding (counts-only; the raw payload is never re-emitted).
    Returns ``[]`` when no injection fixture is declared or the text is clean.
    """
    if not expectation.injection_fixture:
        return []
    fixture_path = expectation.directory / expectation.injection_fixture
    if not fixture_path.is_file():
        return []
    text = fixture_path.read_text(encoding="utf-8", errors="ignore")
    finding = finding_from_scan(scan_and_wrap(text))
    return [finding] if finding is not None else []


def _run_linux_for_scenario(expectation: ScenarioExpectation) -> list[Finding]:
    """Run the Linux detectors on the scenario's linux_artifacts fixture.

    The fixture may be either a **directory** (a synthetic mounted-image root,
    walked by the raw Linux parsers to produce the detector dict) or a JSON
    **file** already shaped like the detector's contract (systemd_units,
    cron_entries, ld_preload, sudoers, bashrc_entries, auth_events,
    shell_history). ``LinuxPersistenceDetector``, ``LinuxAuthDetector``,
    ``LinuxExecutionDetector``, ``LinuxLoginSessionDetector`` and
    ``LinuxProcessDetector`` all consume the same collected dict. Returns
    ``[]`` when no linux_artifacts fixture is declared.
    """
    from sift_find_evil.detectors import (
        LinuxAuthDetector,
        LinuxExecutionDetector,
        LinuxLoginSessionDetector,
        LinuxPersistenceDetector,
        LinuxProcessDetector,
    )

    artifacts = _load_linux_artifacts(expectation)
    if artifacts is None:
        return []
    findings = LinuxPersistenceDetector().analyze(artifacts)
    findings.extend(LinuxAuthDetector().analyze(artifacts))
    findings.extend(LinuxExecutionDetector().analyze(artifacts))
    findings.extend(LinuxLoginSessionDetector().analyze(artifacts))
    findings.extend(LinuxProcessDetector().analyze(artifacts))
    return findings


def _load_linux_artifacts(expectation: ScenarioExpectation) -> Optional[dict]:
    """Load the scenario's linux_artifacts fixture into the detector dict.

    Directory fixtures are walked by the raw Linux parsers; JSON fixtures are
    already shaped like the detector contract. Returns ``None`` when no fixture
    is declared or the path resolves to neither a directory nor a file.
    """
    if not expectation.linux_artifacts_fixture:
        return None
    fixture_path = expectation.directory / expectation.linux_artifacts_fixture
    if fixture_path.is_dir():
        from sift_find_evil.parsers import collect_linux_artifacts

        return collect_linux_artifacts(fixture_path)
    if fixture_path.is_file():
        with fixture_path.open(encoding="utf-8") as handle:
            return json.load(handle)
    return None


def _run_hidden_process_for_scenario(expectation: ScenarioExpectation) -> list[Finding]:
    """Cross-source T1014 check: PID in the ``linux.pslist`` memory view but
    absent from the ``/proc`` capture (a getdents-hook rootkit signal).

    Needs BOTH a ``memory.linux_pslist`` fixture and a ``linux_artifacts`` /proc
    capture; returns ``[]`` otherwise. Mirrors the two assembly points on the
    shipping CLI path where ``--memory`` and ``--linux-artifacts`` coexist.
    """
    pslist_rel = expectation.memory_fixtures.get("linux_pslist")
    if not pslist_rel:
        return []
    pslist_path = expectation.directory / pslist_rel
    if not pslist_path.is_file():
        return []
    with pslist_path.open(encoding="utf-8") as handle:
        raw_rows = json.load(handle)
    if not isinstance(raw_rows, list):
        return []
    pslist_rows = coerce_streams({"linux_pslist": raw_rows}).get("linux_pslist")

    artifacts = _load_linux_artifacts(expectation)
    proc_rows = artifacts.get("proc_processes") if artifacts else None

    return detect_hidden_linux_processes(proc_rows, pslist_rows)


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

    injection_findings = _run_injection_for_scenario(expectation)
    findings.extend(injection_findings)

    linux_findings = _run_linux_for_scenario(expectation)
    findings.extend(linux_findings)

    # Cross-source T1014: a PID in the linux.pslist memory view but absent from
    # the /proc capture is hidden by a userland getdents hook. Needs both the
    # memory pslist rows and the /proc rows, so it runs after both are loaded.
    hidden_process_findings = _run_hidden_process_for_scenario(expectation)
    findings.extend(hidden_process_findings)

    sigma_findings = _run_sigma_for_scenario(expectation)
    findings.extend(sigma_findings)

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
        # Extras beyond the expected count are false positives, not free passes:
        # the count block otherwise only ever adds tp/fn, so an over-emitting
        # detector would mask a precision regression as precision=1.00.
        extra = max(len(matched) - webmail_expected, 0)
        fp.extend(["webmail_exfiltration"] * extra)

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
        # Extras beyond the expected count are false positives (see webmail).
        extra = max(len(matched) - cloud_expected, 0)
        fp.extend(["cloud_upload"] * extra)

    yara_expected = expectation.finding_counts.get("yara_match", 0)
    if yara_expected:
        matched = [
            f for f in yara_findings if f.category.value == "malware_classification"
        ]
        tp.extend(["yara_match"] * min(yara_expected, len(matched)))
        missing = max(yara_expected - len(matched), 0)
        fn.extend(["yara_match"] * missing)
        # Extras beyond the expected count are false positives (see webmail).
        extra = max(len(matched) - yara_expected, 0)
        fp.extend(["yara_match"] * extra)

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

    injection_expected = expectation.finding_counts.get("injection_attempt", 0)
    matched_count = len(injection_findings)
    if injection_expected:
        tp.extend(["injection_attempt"] * min(injection_expected, matched_count))
        missing = max(injection_expected - matched_count, 0)
        fn.extend(["injection_attempt"] * missing)
        extra = max(matched_count - injection_expected, 0)
        fp.extend(["injection_attempt"] * extra)
    elif matched_count:
        # An injection finding fired where none was expected: a false positive
        # (e.g. a benign scenario whose text tripped the detector).
        fp.extend(["injection_attempt"] * matched_count)

    sigma_expected = expectation.finding_counts.get("sigma_match", 0)
    sigma_matched = len(sigma_findings)
    if sigma_expected:
        tp.extend(["sigma_match"] * min(sigma_expected, sigma_matched))
        missing = max(sigma_expected - sigma_matched, 0)
        fn.extend(["sigma_match"] * missing)
        extra = max(sigma_matched - sigma_expected, 0)
        fp.extend(["sigma_match"] * extra)
    elif sigma_matched:
        # A Sigma rule fired where none was expected (e.g. the clean baseline):
        # a false positive. This is the guard that keeps a mis-tuned rule from
        # silently degrading precision - it must show up as an FP, not vanish.
        fp.extend(["sigma_match"] * sigma_matched)

    persistence_expected = expectation.finding_counts.get("persistence", 0)
    if persistence_expected:
        matched = [f for f in findings if f.category.value == "persistence"]
        tp.extend(["persistence"] * min(persistence_expected, len(matched)))
        missing = max(persistence_expected - len(matched), 0)
        fn.extend(["persistence"] * missing)
        # Extras beyond the expected count are false positives, not free passes:
        # without this a detector that hallucinates persistence findings would
        # score precision=1.00 (the count block otherwise only ever adds tp/fn).
        extra = max(len(matched) - persistence_expected, 0)
        fp.extend(["persistence"] * extra)

    credential_expected = expectation.finding_counts.get("credential_access", 0)
    if credential_expected:
        matched = [f for f in findings if f.category.value == "credential_access"]
        tp.extend(["credential_access"] * min(credential_expected, len(matched)))
        missing = max(credential_expected - len(matched), 0)
        fn.extend(["credential_access"] * missing)
        # Extras beyond the expected count are false positives (see persistence).
        extra = max(len(matched) - credential_expected, 0)
        fp.extend(["credential_access"] * extra)

    execution_expected = expectation.finding_counts.get("execution", 0)
    if execution_expected:
        matched = [f for f in findings if f.category.value == "execution"]
        tp.extend(["execution"] * min(execution_expected, len(matched)))
        missing = max(execution_expected - len(matched), 0)
        fn.extend(["execution"] * missing)
        # Extras beyond the expected count are false positives (see persistence).
        extra = max(len(matched) - execution_expected, 0)
        fp.extend(["execution"] * extra)

    # Linux /proc hidden/suspicious-process surface (LinuxProcessDetector,
    # SFE-4fnv.6). Matched by a ``proc``-only artifact source (proc present,
    # memory absent) rather than by category, so it collides neither with the
    # memory detector's own PROCESS_INJECTION findings (artifact_sources=
    # ["memory"]) nor with the cross-source divergence finding below
    # (artifact_sources=["memory", "proc"], SFE-6mqd) -- the memory-absent clause
    # keeps the two keys mutually exclusive.
    hidden_process_expected = expectation.finding_counts.get("hidden_process", 0)
    if hidden_process_expected:
        matched = [
            f
            for f in findings
            if "proc" in (f.artifact_sources or [])
            and "memory" not in (f.artifact_sources or [])
        ]
        tp.extend(["hidden_process"] * min(hidden_process_expected, len(matched)))
        missing = max(hidden_process_expected - len(matched), 0)
        fn.extend(["hidden_process"] * missing)
        # Extras beyond the expected count are false positives (see persistence).
        extra = max(len(matched) - hidden_process_expected, 0)
        fp.extend(["hidden_process"] * extra)

    # Cross-source hidden-process divergence (SFE-6mqd): a PID in the linux.pslist
    # memory view but absent from the /proc capture (T1014 getdents hook). Matched
    # by carrying BOTH the ``memory`` AND ``proc`` artifact sources, which uniquely
    # selects the correlation finding: the /proc detector emits ``proc`` only and
    # the memory detector emits ``memory`` only, so this never collides with the
    # ``hidden_process`` key above or the ``memory_finding`` key.
    divergence_expected = expectation.finding_counts.get("hidden_process_divergence", 0)
    if divergence_expected:
        matched = [
            f
            for f in findings
            if "memory" in (f.artifact_sources or [])
            and "proc" in (f.artifact_sources or [])
        ]
        tp.extend(
            ["hidden_process_divergence"] * min(divergence_expected, len(matched))
        )
        missing = max(divergence_expected - len(matched), 0)
        fn.extend(["hidden_process_divergence"] * missing)
        # Extras beyond the expected count are false positives (see persistence).
        extra = max(len(matched) - divergence_expected, 0)
        fp.extend(["hidden_process_divergence"] * extra)

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
    # Raw evidence for INDEPENDENT anchor re-derivation: the adversarial falsifier
    # re-derives a finding's asserted IP/PID against the RAW tool output, not the
    # finding's narrative - so a hallucinated anchor is killed even if the finding's
    # own reasoning cites it.
    #
    # Per-finding PROVENANCE (SFE-fsno): when a finding carries a ``source_span``
    # (the specific tool-output record it was derived from), re-derive against THAT
    # span, not the whole-corpus blob. This upgrades the check from "anchor exists
    # somewhere in the corpus" to "anchor exists in THIS finding's own source", so a
    # real-but-MISATTRIBUTED anchor (a PID/IP that belongs to a different finding's
    # record) is caught. Findings without a span fall back to the corpus blob, so
    # un-instrumented detectors keep their existing (blob-wide) behavior unchanged.
    raw_evidence = _scenario_raw_evidence(expectation.directory)
    evidence_texts = {
        f.title: (f.evidence.get("source_span") or raw_evidence) for f in findings
    }
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
        findings=findings,
    )


def aggregate(results: list[ScenarioResult]) -> dict[str, Any]:
    """Compute micro-averaged precision/recall/F1 across all scenarios."""
    tp = sum(len(r.true_positives) for r in results)
    fp = sum(len(r.false_positives) for r in results)
    fn = sum(len(r.false_negatives) for r in results)

    precision = tp / (tp + fp) if (tp + fp) else 1.0
    recall = tp / (tp + fn) if (tp + fn) else 1.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0

    # Cross-source correlation is a hardening overlay, not part of P/R/F1. Surface
    # its totals so the report shows the capability is load-bearing on the real
    # corpus (SFE-1fkn) rather than only exercised by a unit test.
    correlations = sum(len(r.hardening.correlations) for r in results)
    co_occurrences = sum(len(r.hardening.co_occurrences) for r in results)
    # Entity-keyed cross-artifact corroboration overlay (SFE-fx8o), surfaced so
    # the report shows it is load-bearing on the real corpus, not only unit-tested.
    corroborations = sum(len(r.hardening.corroborations) for r in results)
    # Sigma matches (SFE-katy), surfaced for the same reason: proof the wired
    # Sigma corpus fires on the real corpus rather than only in unit tests.
    sigma_matches = sum(
        sum(1 for f in r.findings if "sigma_scan" in (f.artifact_sources or []))
        for r in results
    )
    # Subject-risk band totals (SFE-dkfr): count scored subjects per band across
    # the run, so the report shows the risk overlay discriminates on the real
    # corpus (clean baseline scores no subjects; incident scenarios raise CRIT/
    # HIGH) rather than only firing in unit tests.
    band_totals = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for r in results:
        for subject in r.hardening.subject_risk:
            band = subject.get("band")
            if band in band_totals:
                band_totals[band] += 1

    return {
        "true_positives": tp,
        "false_positives": fp,
        "false_negatives": fn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "cross_source_correlations": correlations,
        "cross_source_co_occurrences": co_occurrences,
        "cross_artifact_corroborations": corroborations,
        "sigma_matches": sigma_matches,
        "subjects_critical": band_totals["critical"],
        "subjects_high": band_totals["high"],
        "subjects_medium": band_totals["medium"],
        "subjects_low": band_totals["low"],
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
                        "cross_source_correlations": len(r.hardening.correlations),
                        "cross_source_co_occurrences": len(r.hardening.co_occurrences),
                        # Highest-risk subject for this scenario (SFE-dkfr), or
                        # None when nothing scored (e.g. a clean baseline). The
                        # full list lives in the scenario's HardeningReport.
                        "top_risk_subject": (
                            r.hardening.subject_risk[0]
                            if r.hardening.subject_risk
                            else None
                        ),
                        # Receipts (SFE-cahy): count of publicly-verifiable
                        # Ed25519 receipts and the Merkle root binding the set,
                        # so the report shows public-key receipts are the
                        # load-bearing default on the scored path.
                        "signed_receipts": r.hardening.signed_receipts,
                        "merkle_root": r.hardening.merkle_root,
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
