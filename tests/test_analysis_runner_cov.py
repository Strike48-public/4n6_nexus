"""Coverage-focused tests for AnalysisRunner.

These tests drive the remaining uncovered branches of the phase orchestrator:
full/custom mode dispatch, the per-phase "no evidence path" guards, cancellation
short-circuits, per-file parse-error handlers, and the outer try/except wrappers
that log a phase error and still call complete_phase(). They complement
tests/test_analysis_runner.py (owned by another agent) which covers the happy
paths against real synthetic fixtures.

We use lightweight fakes/monkeypatching for the error/guard paths rather than
real forensic libraries, in line with the module's Protocol-based duck typing.
"""

from __future__ import annotations

import asyncio
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
    return []


@pytest.fixture
def tracker(activity_log: list[str]) -> ProgressTracker:
    t = ProgressTracker()
    t.on_activity_added(lambda activity: activity_log.append(activity.message))
    return t


@pytest.fixture
def runner(tracker: ProgressTracker) -> AnalysisRunner:
    return AnalysisRunner(tracker)


class _Finding:
    """Minimal duck-typed finding: severity + title + description."""

    def __init__(self, severity: str, title: str, description: str = "") -> None:
        self.severity = severity
        self.title = title
        self.description = description


# --- run_analysis mode dispatch -------------------------------------------


def test_run_analysis_full_mode_runs_all_phases_with_empty_evidence(
    runner: AnalysisRunner,
    tracker: ProgressTracker,
    tmp_path: Path,
    activity_log: list[str],
):
    """Full mode dispatches through every phase (lines 67, 99-114).

    With an existing-but-empty evidence dir, each detection phase discovers no
    fixtures and logs a skip, yet the report phase still completes the run.
    """
    runner.configure(tmp_path, "full")
    _run(runner.run_analysis())
    assert tracker.is_running is False
    assert any("Analysis complete" in a for a in activity_log)


def test_run_analysis_custom_mode_delegates_to_full(
    runner: AnalysisRunner,
    tracker: ProgressTracker,
    tmp_path: Path,
    activity_log: list[str],
):
    """Custom mode falls through to _run_custom_analysis -> full (lines 74, 131)."""
    runner.configure(tmp_path, "custom")
    _run(runner.run_analysis())
    assert any("Analysis complete" in a for a in activity_log)


def test_run_analysis_reraises_and_logs_on_phase_error(
    runner: AnalysisRunner,
    tracker: ProgressTracker,
    tmp_path: Path,
    activity_log: list[str],
):
    """An unexpected error inside dispatch is logged and re-raised (lines 76-78).

    is_running must still be reset by the finally block.
    """

    async def _boom() -> None:
        raise RuntimeError("kaboom")

    runner.configure(tmp_path, "quick")
    runner._run_quick_analysis = _boom  # type: ignore[method-assign]

    with pytest.raises(RuntimeError, match="kaboom"):
        _run(runner.run_analysis())

    assert tracker.is_running is False
    assert any("Analysis error: kaboom" in a for a in activity_log)


# --- prefetch phase branches ----------------------------------------------


def test_prefetch_phase_skips_when_no_csv_and_not_windows(
    runner: AnalysisRunner,
    tracker: ProgressTracker,
    tmp_path: Path,
    activity_log: list[str],
):
    """Empty dir (no prefetch.csv, no Windows tree) hits the plain skip (line 224)."""
    runner.configure(tmp_path, "quick")
    _run(runner._phase_prefetch_analysis())
    assert any("no prefetch.csv found" in a for a in activity_log)


def test_prefetch_phase_cancellation(
    runner: AnalysisRunner,
    tracker: ProgressTracker,
    tmp_path: Path,
    activity_log: list[str],
):
    """A canceled tracker breaks out of the prefetch loop (lines 240-243)."""
    shutil.copy(SYNTHETIC / "02_ransomware" / "prefetch.csv", tmp_path / "prefetch.csv")
    runner.configure(tmp_path, "quick")
    tracker.cancel()
    _run(runner._phase_prefetch_analysis())
    assert any("Prefetch analysis canceled" in a for a in activity_log)


def test_prefetch_phase_parse_error_is_logged(
    runner: AnalysisRunner,
    tracker: ProgressTracker,
    tmp_path: Path,
    activity_log: list[str],
    monkeypatch,
):
    """A per-file parse error is caught and logged (lines 274-275)."""
    (tmp_path / "prefetch.csv").write_text("garbage")
    runner.configure(tmp_path, "quick")

    from sift_find_evil.parsers import prefetch_parser

    def _raise(self, path):
        raise ValueError("bad csv")

    monkeypatch.setattr(prefetch_parser.PrefetchParser, "parse_csv", _raise)
    _run(runner._phase_prefetch_analysis())
    assert any("Prefetch parse error" in a for a in activity_log)


def test_prefetch_phase_outer_exception_handled(
    runner: AnalysisRunner,
    tracker: ProgressTracker,
    tmp_path: Path,
    activity_log: list[str],
    monkeypatch,
):
    """A non-parse error (e.g. start_phase blowing up) hits the outer except (284-286)."""
    (tmp_path / "prefetch.csv").write_text("x")
    runner.configure(tmp_path, "quick")

    original_start = tracker.start_phase

    def _boom(name, items_total=0):
        if name == "prefetch":
            raise RuntimeError("phase boom")
        return original_start(name, items_total=items_total)

    monkeypatch.setattr(tracker, "start_phase", _boom)
    _run(runner._phase_prefetch_analysis())
    assert any("Prefetch analysis phase error" in a for a in activity_log)


# --- timestamp phase branches ---------------------------------------------


def test_timestamp_phase_skips_without_evidence_path(
    runner: AnalysisRunner,
    tracker: ProgressTracker,
    activity_log: list[str],
):
    """Timestamp phase logs a skip when evidence path is unset (lines 291-294)."""
    _run(runner._phase_timestamp_analysis())
    assert any("no evidence path" in a for a in activity_log)


def test_timestamp_phase_cancellation(
    runner: AnalysisRunner,
    tracker: ProgressTracker,
    tmp_path: Path,
    activity_log: list[str],
):
    """A canceled tracker breaks out of the timestamp loop (lines 328-331)."""
    src = SYNTHETIC / "03_timestomping"
    for name in ("mft.csv", "prefetch.csv", "evtx.csv"):
        shutil.copy(src / name, tmp_path / name)
    runner.configure(tmp_path, "timeline")
    tracker.cancel()
    _run(runner._phase_timestamp_analysis())
    assert any("Timestamp analysis canceled" in a for a in activity_log)


def test_timestamp_phase_parse_error_logged(
    runner: AnalysisRunner,
    tracker: ProgressTracker,
    tmp_path: Path,
    activity_log: list[str],
    monkeypatch,
):
    """A per-file parse error inside the timestamp loop is logged (lines 395-396)."""
    src = SYNTHETIC / "03_timestomping"
    for name in ("mft.csv", "prefetch.csv", "evtx.csv"):
        shutil.copy(src / name, tmp_path / name)
    runner.configure(tmp_path, "timeline")

    from sift_find_evil.parsers import mft_parser

    def _raise(self, path):
        raise ValueError("mft boom")

    monkeypatch.setattr(mft_parser.MFTParser, "parse_csv", _raise)
    _run(runner._phase_timestamp_analysis())
    assert any("Timestamp analysis error" in a for a in activity_log)


def test_timestamp_phase_outer_exception_handled(
    runner: AnalysisRunner,
    tracker: ProgressTracker,
    tmp_path: Path,
    activity_log: list[str],
    monkeypatch,
):
    """An error before the loop hits the outer except (lines 400-402)."""
    src = SYNTHETIC / "03_timestomping"
    for name in ("mft.csv", "prefetch.csv", "evtx.csv"):
        shutil.copy(src / name, tmp_path / name)
    runner.configure(tmp_path, "timeline")

    original_start = tracker.start_phase

    def _boom(name, items_total=0):
        if name == "timestamps":
            raise RuntimeError("ts boom")
        return original_start(name, items_total=items_total)

    monkeypatch.setattr(tracker, "start_phase", _boom)
    _run(runner._phase_timestamp_analysis())
    assert any("Timestamp analysis phase error" in a for a in activity_log)


# --- YARA phase branches ---------------------------------------------------


def test_yara_phase_skips_when_rules_missing(
    runner: AnalysisRunner,
    tracker: ProgressTracker,
    tmp_path: Path,
    activity_log: list[str],
    monkeypatch,
):
    """When the rules dir does not exist the phase skips (lines 420-423)."""
    runner.configure(tmp_path, "quick")

    # Monkeypatch Path.exists to return False only for the rules dir, so the
    # phase reaches the "rules not found" guard regardless of submodule state.
    original_exists = Path.exists

    def _exists(self):
        if "signature-base" in str(self):
            return False
        return original_exists(self)

    monkeypatch.setattr(Path, "exists", _exists)
    _run(runner._phase_yara_scan())
    assert any("rules not found" in a for a in activity_log)


def test_yara_phase_scanner_init_failure(
    runner: AnalysisRunner,
    tracker: ProgressTracker,
    tmp_path: Path,
    activity_log: list[str],
    monkeypatch,
):
    """If compile_from_directory raises, the phase logs init failure (431-433)."""
    runner.configure(tmp_path, "quick")

    import sift_find_evil.analysis_runner as ar

    original_exists = Path.exists

    def _exists(self):
        if "signature-base" in str(self):
            return True
        return original_exists(self)

    monkeypatch.setattr(Path, "exists", _exists)

    def _raise(cls, rules_dir):
        raise RuntimeError("compile failed")

    monkeypatch.setattr(ar.YaraScanner, "compile_from_directory", classmethod(_raise))
    _run(runner._phase_yara_scan())
    assert any("YARA scanner init failed" in a for a in activity_log)


def test_yara_phase_cancellation(
    runner: AnalysisRunner,
    tracker: ProgressTracker,
    tmp_path: Path,
    activity_log: list[str],
    monkeypatch,
):
    """A canceled tracker breaks out of the YARA file loop (lines 463-464)."""
    (tmp_path / "sample.bin").write_bytes(b"data")
    runner.configure(tmp_path, "quick")

    import sift_find_evil.analysis_runner as ar

    original_exists = Path.exists

    def _exists(self):
        if "signature-base" in str(self):
            return True
        return original_exists(self)

    monkeypatch.setattr(Path, "exists", _exists)

    class _FakeScanner:
        pass

    class _FakeDetector:
        def __init__(self, scanner):
            pass

        def analyze_file(self, path):
            return []

    monkeypatch.setattr(
        ar.YaraScanner,
        "compile_from_directory",
        classmethod(lambda cls, rules_dir: _FakeScanner()),
    )
    monkeypatch.setattr(ar, "YaraDetector", _FakeDetector)

    tracker.cancel()
    _run(runner._phase_yara_scan())
    assert any("YARA scan canceled" in a for a in activity_log)


def test_yara_phase_maps_findings_and_handles_scan_error(
    runner: AnalysisRunner,
    tracker: ProgressTracker,
    tmp_path: Path,
    activity_log: list[str],
    monkeypatch,
):
    """A finding is mapped (472-474) and a per-file scan error is logged (476-477)."""
    (tmp_path / "good.bin").write_bytes(b"a")
    (tmp_path / "bad.bin").write_bytes(b"b")
    runner.configure(tmp_path, "quick")

    import sift_find_evil.analysis_runner as ar

    original_exists = Path.exists

    def _exists(self):
        if "signature-base" in str(self):
            return True
        return original_exists(self)

    monkeypatch.setattr(Path, "exists", _exists)

    class _FakeScanner:
        pass

    class _FakeDetector:
        def __init__(self, scanner):
            pass

        def analyze_file(self, path):
            if path.name == "bad.bin":
                raise RuntimeError("scan exploded")
            return [_Finding("high", "Malware match")]

    monkeypatch.setattr(
        ar.YaraScanner,
        "compile_from_directory",
        classmethod(lambda cls, rules_dir: _FakeScanner()),
    )
    monkeypatch.setattr(ar, "YaraDetector", _FakeDetector)

    _run(runner._phase_yara_scan())
    assert any("YARA: Malware match" in a for a in activity_log)
    assert any("YARA scan error on bad.bin" in a for a in activity_log)
    assert any(f.title == "Malware match" for f in tracker.findings)


def test_yara_phase_outer_exception_handled(
    runner: AnalysisRunner,
    tracker: ProgressTracker,
    tmp_path: Path,
    activity_log: list[str],
    monkeypatch,
):
    """An error after scanner init (in start_phase) hits the outer except (486-488)."""
    (tmp_path / "x.bin").write_bytes(b"a")
    runner.configure(tmp_path, "quick")

    import sift_find_evil.analysis_runner as ar

    original_exists = Path.exists

    def _exists(self):
        if "signature-base" in str(self):
            return True
        return original_exists(self)

    monkeypatch.setattr(Path, "exists", _exists)

    class _FakeScanner:
        pass

    class _FakeDetector:
        def __init__(self, scanner):
            pass

    monkeypatch.setattr(
        ar.YaraScanner,
        "compile_from_directory",
        classmethod(lambda cls, rules_dir: _FakeScanner()),
    )
    monkeypatch.setattr(ar, "YaraDetector", _FakeDetector)

    original_start = tracker.start_phase

    def _boom(name, items_total=0):
        if name == "yara":
            raise RuntimeError("yara phase boom")
        return original_start(name, items_total=items_total)

    monkeypatch.setattr(tracker, "start_phase", _boom)
    _run(runner._phase_yara_scan())
    assert any("YARA scan phase error" in a for a in activity_log)


# --- memory phase branches -------------------------------------------------


def test_memory_phase_skips_without_evidence_path(
    runner: AnalysisRunner,
    tracker: ProgressTracker,
    activity_log: list[str],
):
    """Memory phase logs a skip when evidence path is unset (lines 493-496)."""
    _run(runner._phase_memory_analysis())
    assert any("no evidence path" in a for a in activity_log)


def test_memory_phase_malformed_rows_skipped(
    runner: AnalysisRunner,
    tracker: ProgressTracker,
    tmp_path: Path,
    activity_log: list[str],
):
    """A fixture whose plugin value is not iterable raises TypeError (571-575).

    pslist is null here, so the list comprehension `for row in None` raises
    TypeError inside the coercion try-block and the fixture is skipped with a
    'Malformed fixture' log.
    """
    fixtures_dir = tmp_path / "memory_fixtures"
    fixtures_dir.mkdir()
    (fixtures_dir / "bad.json").write_text('{"pslist": null}')
    runner.configure(tmp_path, "memory")
    _run(runner._phase_memory_analysis())
    assert any("Malformed fixture" in a for a in activity_log)


def test_memory_phase_outer_exception_handled(
    runner: AnalysisRunner,
    tracker: ProgressTracker,
    tmp_path: Path,
    activity_log: list[str],
    monkeypatch,
):
    """An error before the loop hits the outer except (lines 602-604)."""
    fixtures_dir = tmp_path / "memory_fixtures"
    fixtures_dir.mkdir()
    (fixtures_dir / "f.json").write_text('{"pslist": []}')
    runner.configure(tmp_path, "memory")

    original_start = tracker.start_phase

    def _boom(name, items_total=0):
        if name == "memory":
            raise RuntimeError("mem boom")
        return original_start(name, items_total=items_total)

    monkeypatch.setattr(tracker, "start_phase", _boom)
    _run(runner._phase_memory_analysis())
    assert any("Memory analysis phase error" in a for a in activity_log)


# --- persistence phase branches --------------------------------------------


def test_persistence_phase_skips_without_evidence_path(
    runner: AnalysisRunner,
    tracker: ProgressTracker,
    activity_log: list[str],
):
    """Persistence phase logs a skip when evidence path is unset (609-612)."""
    _run(runner._phase_persistence_detection())
    assert any("no evidence path" in a for a in activity_log)


def test_persistence_phase_cancellation(
    runner: AnalysisRunner,
    tracker: ProgressTracker,
    tmp_path: Path,
    activity_log: list[str],
):
    """A canceled tracker breaks out of the registry parse loop (652-655)."""
    src = SYNTHETIC / "08_persistence_run_keys"
    copied = False
    for csv in ("run_keys.csv", "amcache.csv", "bam.csv", "shimcache.csv"):
        if (src / csv).exists():
            shutil.copy(src / csv, tmp_path / csv)
            copied = True
    if not copied:
        # Fall back to a minimal shimcache fixture so total_files > 0.
        (tmp_path / "shimcache.csv").write_text("path\nC:/x.exe\n")
    runner.configure(tmp_path, "full")
    tracker.cancel()
    _run(runner._phase_persistence_detection())
    assert any("Registry analysis canceled" in a for a in activity_log)


def test_persistence_phase_parse_branches_and_error(
    runner: AnalysisRunner,
    tracker: ProgressTracker,
    tmp_path: Path,
    activity_log: list[str],
    monkeypatch,
):
    """Drive the shimcache/userassist parse branches plus a parse error (660,666,677-678).

    We provide shimcache + userassist fixtures and force the shimcache parser to
    raise so the except handler (677-678) fires, while userassist parses normally
    (line 666) and the else branch stays unused.
    """
    (tmp_path / "shimcache.csv").write_text("bad")
    (tmp_path / "userassist.csv").write_text("bad")
    runner.configure(tmp_path, "full")

    from sift_find_evil.parsers import registry_parser

    def _shim_raise(self, path):
        raise ValueError("shim boom")

    def _ua_ok(self, path):
        return []

    monkeypatch.setattr(
        registry_parser.RegistryParser, "parse_shimcache_csv", _shim_raise
    )
    monkeypatch.setattr(registry_parser.RegistryParser, "parse_userassist_csv", _ua_ok)
    _run(runner._phase_persistence_detection())
    assert any("Registry parse error on shimcache.csv" in a for a in activity_log)


def test_persistence_phase_bam_branch(
    runner: AnalysisRunner,
    tracker: ProgressTracker,
    tmp_path: Path,
    activity_log: list[str],
    monkeypatch,
):
    """The bam parse branch (line 664) is exercised via a bam fixture."""
    (tmp_path / "bam.csv").write_text("bad")
    runner.configure(tmp_path, "full")

    from sift_find_evil.parsers import registry_parser

    monkeypatch.setattr(
        registry_parser.RegistryParser, "parse_bam_csv", lambda self, path: []
    )
    _run(runner._phase_persistence_detection())
    assert any("Parsed 0 bam entries" in a for a in activity_log)


def test_persistence_phase_outer_exception_handled(
    runner: AnalysisRunner,
    tracker: ProgressTracker,
    tmp_path: Path,
    activity_log: list[str],
    monkeypatch,
):
    """An error before the loop hits the outer except (lines 706-710)."""
    (tmp_path / "shimcache.csv").write_text("x")
    runner.configure(tmp_path, "full")

    original_start = tracker.start_phase

    def _boom(name, items_total=0):
        if name == "persist":
            raise RuntimeError("persist boom")
        return original_start(name, items_total=items_total)

    monkeypatch.setattr(tracker, "start_phase", _boom)
    _run(runner._phase_persistence_detection())
    assert any("Persistence detection phase error" in a for a in activity_log)


def test_severity_mapping_used_in_findings(
    runner: AnalysisRunner, tracker: ProgressTracker
):
    """Sanity: _map_finding_severity produces expected enum for a fake finding."""
    f = _Finding("critical", "x")
    assert runner._map_finding_severity(f.severity) == FindingSeverity.CRITICAL
