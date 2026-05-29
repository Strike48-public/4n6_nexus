"""Tests for AnalysisRunner — the phase orchestrator that drives detectors.

These tests exercise the real detection flow (parsers + detectors + self-correction
engine) against synthetic fixtures rather than mocking, so coverage here reflects
genuine end-to-end orchestration confidence, not stubbed behavior. The runner is
the bridge between the TUI and the detection library, so its phase sequencing,
mode selection, fixture discovery, cancellation, and error handling all matter.
"""

from __future__ import annotations

import asyncio
import importlib.util
import json
import shutil
from pathlib import Path

import pytest

from sift_find_evil.analysis_runner import AnalysisRunner
from sift_find_evil.progress_tracker import FindingSeverity, ProgressTracker

SYNTHETIC = Path(__file__).parent.parent / "scenarios" / "synthetic"


def _run(coro):
    """Drive an async coroutine to completion in a fresh event loop."""
    return asyncio.run(coro)


@pytest.fixture
def activity_log() -> list[str]:
    """Captures every activity message (the tracker itself keeps only the last 5)."""
    return []


@pytest.fixture
def tracker(activity_log: list[str]) -> ProgressTracker:
    """A fresh progress tracker that records all activity into activity_log.

    ProgressTracker.activities is a rolling buffer of the last 5 messages, so we
    subscribe to the activity callback to retain the full history for assertions.
    """
    t = ProgressTracker()
    t.on_activity_added(lambda activity: activity_log.append(activity.message))
    return t


@pytest.fixture
def runner(tracker: ProgressTracker) -> AnalysisRunner:
    """An analysis runner wired to a fresh tracker."""
    return AnalysisRunner(tracker)


# --- Configuration and phase registration ---------------------------------


def test_configure_sets_path_and_mode(runner: AnalysisRunner, tmp_path: Path):
    """configure() records evidence path and mode and registers phases."""
    runner.configure(tmp_path, "quick")
    assert runner.evidence_path == tmp_path
    assert runner.mode == "quick"


@pytest.mark.parametrize(
    "mode,expected_phase_ids",
    [
        ("quick", {"load", "prefetch", "yara", "report"}),
        ("memory", {"load", "memory", "report"}),
        ("timeline", {"load", "timestamps", "report"}),
        ("full", {"load", "timestamps", "yara", "memory", "persist", "report"}),
        ("custom", {"load", "timestamps", "yara", "memory", "persist", "report"}),
    ],
)
def test_register_phases_per_mode(
    runner: AnalysisRunner, tracker: ProgressTracker, mode, expected_phase_ids
):
    """Each mode registers its own phase set."""
    runner.configure(Path("/tmp"), mode)
    registered = {p.name for p in tracker.phases}
    assert registered == expected_phase_ids


# --- run_analysis guard rails ----------------------------------------------


def test_run_analysis_without_path_raises(runner: AnalysisRunner):
    """run_analysis refuses to run when no evidence path is configured."""
    with pytest.raises(ValueError, match="Evidence path not configured"):
        _run(runner.run_analysis())


def test_run_analysis_clears_running_flag_on_completion(
    runner: AnalysisRunner, tracker: ProgressTracker, tmp_path: Path
):
    """is_running is reset to False after a successful run."""
    runner.configure(tmp_path, "timeline")
    _run(runner.run_analysis())
    assert tracker.is_running is False


# --- Timeline mode against the real ransomware fixture ---------------------


def test_timeline_mode_detects_findings_on_real_fixture(
    runner: AnalysisRunner,
    tracker: ProgressTracker,
    tmp_path: Path,
    activity_log: list[str],
):
    """Timeline analysis over the timestomping fixture produces real findings.

    Drives MFT/prefetch/evtx parsers + the SelfCorrectionEngine end-to-end.
    """
    src = SYNTHETIC / "03_timestomping"
    for name in ("mft.csv", "prefetch.csv", "evtx.csv"):
        shutil.copy(src / name, tmp_path / name)

    runner.configure(tmp_path, "timeline")
    _run(runner.run_analysis())

    assert len(tracker.findings) > 0
    # report phase always runs last and logs completion
    assert any("Analysis complete" in a for a in activity_log)


def test_timeline_mode_skips_when_fixtures_missing(
    runner: AnalysisRunner,
    tracker: ProgressTracker,
    tmp_path: Path,
    activity_log: list[str],
):
    """Timeline analysis logs a skip when MFT/prefetch/evtx are absent."""
    runner.configure(tmp_path, "timeline")
    _run(runner.run_analysis())
    assert any("missing MFT/prefetch/evtx" in a for a in activity_log)


# --- Quick mode + prefetch heuristic ---------------------------------------


def test_quick_mode_flags_suspicious_prefetch(
    runner: AnalysisRunner, tracker: ProgressTracker, tmp_path: Path
):
    """Quick analysis flags living-off-the-land binaries in prefetch."""
    # The ransomware fixture's prefetch contains CMD.EXE etc.
    shutil.copy(SYNTHETIC / "02_ransomware" / "prefetch.csv", tmp_path / "prefetch.csv")

    runner.configure(tmp_path, "quick")
    _run(runner.run_analysis())

    titles = [f.title for f in tracker.findings]
    assert any("Suspicious execution" in t for t in titles)


def test_prefetch_phase_skips_without_evidence_path(
    runner: AnalysisRunner, tracker: ProgressTracker, activity_log: list[str]
):
    """Prefetch phase logs a skip when evidence path was never set."""
    _run(runner._phase_prefetch_analysis())
    assert any("no evidence path" in a for a in activity_log)


def test_prefetch_phase_detects_raw_windows_filesystem(
    runner: AnalysisRunner,
    tracker: ProgressTracker,
    tmp_path: Path,
    activity_log: list[str],
):
    """A raw Windows tree (no CSVs) triggers the PECmd guidance message."""
    (tmp_path / "Windows").mkdir()
    runner.configure(tmp_path, "quick")
    _run(runner._phase_prefetch_analysis())
    assert any("Real Windows filesystem" in a for a in activity_log)


# --- Memory mode against real Volatility fixtures --------------------------


def test_memory_mode_detects_findings(
    runner: AnalysisRunner, tracker: ProgressTracker, tmp_path: Path
):
    """Memory analysis over real windows_* fixtures produces findings."""
    fixtures_dir = tmp_path / "memory_fixtures"
    fixtures_dir.mkdir()
    src = SYNTHETIC / "12_memory_intrusion" / "memory_fixtures"

    # The runner reads each *.json as a single fixture with named plugin keys.
    # Compose one combined Windows fixture from the per-plugin files.
    combined = {}
    mapping = {
        "windows_pslist.json": "pslist",
        "windows_psscan.json": "psscan",
        "windows_malfind.json": "malfind",
        "windows_cmdline.json": "cmdline",
        "windows_netscan.json": "netscan",
    }
    for fname, key in mapping.items():
        path = src / fname
        if path.exists():
            combined[key] = json.loads(path.read_text())
    (fixtures_dir / "windows.json").write_text(json.dumps(combined))

    runner.configure(tmp_path, "memory")
    _run(runner.run_analysis())

    assert len(tracker.findings) > 0


def test_memory_phase_skips_oversized_fixture(
    runner: AnalysisRunner,
    tracker: ProgressTracker,
    tmp_path: Path,
    activity_log: list[str],
):
    """Memory fixtures larger than 10 MB are skipped with a log message."""
    fixtures_dir = tmp_path / "memory_fixtures"
    fixtures_dir.mkdir()
    big = fixtures_dir / "huge.json"
    # Write > 10 MB of filler wrapped as JSON
    big.write_text('{"pslist": [' + ("0," * (6 * 1024 * 1024)) + "0]}")

    runner.configure(tmp_path, "memory")
    _run(runner._phase_memory_analysis())
    assert any("oversized" in a for a in activity_log)


def test_memory_phase_handles_malformed_json(
    runner: AnalysisRunner,
    tracker: ProgressTracker,
    tmp_path: Path,
    activity_log: list[str],
):
    """A malformed memory fixture is caught and logged, not crashed."""
    fixtures_dir = tmp_path / "memory_fixtures"
    fixtures_dir.mkdir()
    (fixtures_dir / "bad.json").write_text("{not valid json")

    runner.configure(tmp_path, "memory")
    _run(runner._phase_memory_analysis())
    assert any("Memory analysis error" in a for a in activity_log)


def test_memory_phase_skips_without_fixtures(
    runner: AnalysisRunner,
    tracker: ProgressTracker,
    tmp_path: Path,
    activity_log: list[str],
):
    """Memory phase logs a skip when no fixtures directory exists."""
    runner.configure(tmp_path, "memory")
    _run(runner._phase_memory_analysis())
    assert any("no fixtures found" in a for a in activity_log)


# --- Persistence mode against real registry fixtures -----------------------


def test_persistence_mode_detects_run_key_findings(
    runner: AnalysisRunner, tracker: ProgressTracker, tmp_path: Path
):
    """Persistence detection over the run-keys fixture produces findings."""
    src = SYNTHETIC / "08_persistence_run_keys"
    for csv in ("run_keys.csv", "amcache.csv", "bam.csv"):
        if (src / csv).exists():
            shutil.copy(src / csv, tmp_path / csv)

    runner.configure(tmp_path, "full")
    _run(runner._phase_persistence_detection())

    assert len(tracker.findings) > 0


def test_persistence_phase_skips_without_fixtures(
    runner: AnalysisRunner,
    tracker: ProgressTracker,
    tmp_path: Path,
    activity_log: list[str],
):
    """Persistence phase logs a skip when no registry fixtures are present."""
    runner.configure(tmp_path, "full")
    _run(runner._phase_persistence_detection())
    assert any("no registry fixtures" in a for a in activity_log)


# --- Cancellation ----------------------------------------------------------


def test_cancellation_stops_memory_phase(
    runner: AnalysisRunner,
    tracker: ProgressTracker,
    tmp_path: Path,
    activity_log: list[str],
):
    """A canceled tracker short-circuits the per-fixture loop."""
    fixtures_dir = tmp_path / "memory_fixtures"
    fixtures_dir.mkdir()
    (fixtures_dir / "a.json").write_text(json.dumps({"pslist": []}))
    (fixtures_dir / "b.json").write_text(json.dumps({"pslist": []}))

    runner.configure(tmp_path, "memory")
    tracker.cancel()
    _run(runner._phase_memory_analysis())
    assert any("canceled" in a.lower() for a in activity_log)


# --- Severity mapping ------------------------------------------------------


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("critical", FindingSeverity.CRITICAL),
        ("HIGH", FindingSeverity.HIGH),
        ("Medium", FindingSeverity.MEDIUM),
        ("low", FindingSeverity.LOW),
        ("info", FindingSeverity.INFO),
    ],
)
def test_map_finding_severity_known(runner: AnalysisRunner, raw, expected):
    """Known severity strings map to the right enum, case-insensitively."""
    assert runner._map_finding_severity(raw) == expected


def test_map_finding_severity_unknown_defaults_to_medium(
    runner: AnalysisRunner, tracker: ProgressTracker, activity_log: list[str]
):
    """Unknown severities default to MEDIUM and log a warning."""
    result = runner._map_finding_severity("bogus")
    assert result == FindingSeverity.MEDIUM
    assert any("Unknown severity" in a for a in activity_log)


# --- YARA phase guard rails (no rules dir / no path) -----------------------


def test_yara_phase_skips_without_evidence_path(
    runner: AnalysisRunner, tracker: ProgressTracker, activity_log: list[str]
):
    """YARA phase logs a skip when evidence path is unset."""
    _run(runner._phase_yara_scan())
    assert any("no evidence path" in a for a in activity_log)


def test_yara_phase_skips_real_windows_filesystem(
    runner: AnalysisRunner,
    tracker: ProgressTracker,
    tmp_path: Path,
    activity_log: list[str],
):
    """YARA phase refuses to scan a full Windows tree (would take hours).

    The runner only reaches the Windows-filesystem guard after it successfully
    compiles rules, so this test requires the YARA community submodule to be
    not just present but populated with rule files. CI does not check the
    submodule out, so we skip unless real rules exist (an empty directory
    would make the scanner init fail and return before the guard).
    """
    if importlib.util.find_spec("yara") is None:
        pytest.skip("yara-python not installed")
    rules_dir = (
        Path(__file__).parent.parent / "rules" / "yara" / "community" / "signature-base"
    )
    has_rules = rules_dir.exists() and any(rules_dir.rglob("*.yar"))
    if not has_rules:
        pytest.skip("YARA community rules submodule not checked out / empty")

    (tmp_path / "Windows").mkdir()
    runner.configure(tmp_path, "quick")
    _run(runner._phase_yara_scan())
    assert any("Real Windows filesystem" in a for a in activity_log)
