"""Coverage-focused tests for sift_find_evil.scenario_runner.

These drive the dispatch branches in the scenario runner that the existing
suite skips past: the browser_history -> NetworkDetector path, every
RegistryParser fixture branch, the YARA availability/compile guards, and the
evidence-image dispatch through ``detect_from_image``.

This file is owned exclusively by the coverage agent; it does not touch source.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import sift_find_evil.scenario_runner as sr
from sift_find_evil.scenario_runner import (
    load_scenario,
    run_scenario,
    run_scenario_path,
)


REPO_ROOT = Path(__file__).resolve().parent.parent
SYNTHETIC = REPO_ROOT / "scenarios" / "synthetic"


def _write_manifest(tmp_path: Path, body: str) -> Path:
    (tmp_path / "scenario.yaml").write_text(body, encoding="utf-8")
    return tmp_path


# Minimal valid causality-triplet CSVs reused across the registry tests.
_MFT_CSV = (
    "EntryNumber,FileName,ParentPath,Created0x10\n"
    "1,test.exe,C:\\\\Users,2024-01-01T00:00:00Z\n"
)
_PREFETCH_CSV = (
    "SourceFilename,Executable,RunCount,LastRunTime\n"
    "TEST.EXE-ABCD1234.pf,TEST.EXE,1,2024-01-01T00:00:00Z\n"
)
_EVTX_CSV = (
    "TimeCreated,EventId,RecordId,Computer,PayloadData1\n"
    "2024-01-01T00:00:00Z,4688,1,TEST-PC,C:\\\\Users\\\\test.exe\n"
)


def _write_triplet(tmp_path: Path) -> None:
    (tmp_path / "mft.csv").write_text(_MFT_CSV)
    (tmp_path / "prefetch.csv").write_text(_PREFETCH_CSV)
    (tmp_path / "evtx.csv").write_text(_EVTX_CSV)


# ---------------------------------------------------------------------------
# browser_history branch -> NetworkDetector (lines 295-311)
# ---------------------------------------------------------------------------


def test_browser_history_branch_runs_network_detector() -> None:
    """The webmail scenario declares browser_history, driving the MFT-access
    record build and NetworkDetector dispatch in _run_fixture_scenario."""
    report = run_scenario_path(SYNTHETIC / "06_webmail_exfiltration")

    assert report.skipped is False, report.skip_reason
    # The webmail exfil finding flows through network_findings into scoring.
    assert "webmail_exfiltration" in report.true_positives
    assert report.findings_count >= 1


# ---------------------------------------------------------------------------
# RegistryParser fixture branches (lines 333-349)
# ---------------------------------------------------------------------------


def test_registry_shimcache_branch() -> None:
    """shimcache fixture exercises parse_shimcache_csv dispatch."""
    report = run_scenario_path(SYNTHETIC / "09_shimcache_only")

    assert report.skipped is False, report.skip_reason
    assert report.findings_count >= 1


def test_registry_amcache_bam_run_keys_branches() -> None:
    """Persistence scenario declares run_keys + amcache + bam, exercising
    those three RegistryParser dispatch branches together."""
    manifest = load_scenario(SYNTHETIC / "08_persistence_run_keys")
    assert {"run_keys", "amcache", "bam"} <= set(manifest.fixtures)

    report = run_scenario(manifest)

    assert report.skipped is False, report.skip_reason
    assert report.findings_count >= 1


def test_registry_userassist_branch(tmp_path: Path) -> None:
    """A scenario declaring userassist drives parse_userassist_csv dispatch.

    No shipped synthetic scenario uses userassist, so we synthesize one with
    the causality triplet (to satisfy the required-fixture gate) plus a
    userassist.csv whose entries are benign (no findings expected)."""
    _write_manifest(
        tmp_path,
        "name: userassist_branch\n"
        "tier: synthetic\n"
        "fixtures:\n"
        "  mft: mft.csv\n"
        "  prefetch: prefetch.csv\n"
        "  evtx: evtx.csv\n"
        "  userassist: userassist.csv\n"
        "expected:\n"
        "  malicious_executables: []\n",
    )
    _write_triplet(tmp_path)
    (tmp_path / "userassist.csv").write_text(
        "program_name,run_count,last_execution,focus_count,focus_time_ms\n"
        "notepad.exe,5,2024-01-01 10:30:00,3,12500\n"
    )

    manifest = load_scenario(tmp_path)
    report = run_scenario(manifest)

    # The userassist branch ran (no exception); benign data yields no FPs.
    assert report.skipped is False, report.skip_reason
    assert report.false_positives == []


def test_registry_no_paths_returns_empty(tmp_path: Path) -> None:
    """When the causality triplet is present but no registry fixture is
    declared, _run_registry hits its early `not any(paths.values())` return."""
    _write_manifest(
        tmp_path,
        "name: no_registry\n"
        "tier: synthetic\n"
        "fixtures:\n"
        "  mft: mft.csv\n"
        "  prefetch: prefetch.csv\n"
        "  evtx: evtx.csv\n"
        "expected:\n"
        "  malicious_executables: []\n",
    )
    _write_triplet(tmp_path)

    manifest = load_scenario(tmp_path)
    report = run_scenario(manifest)

    assert report.skipped is False, report.skip_reason
    assert report.false_positives == []


# ---------------------------------------------------------------------------
# _run_yara guards (lines 361, 371-372)
# ---------------------------------------------------------------------------


def test_run_yara_returns_empty_when_unavailable(tmp_path: Path, monkeypatch) -> None:
    """When yara-python is unavailable, _run_yara short-circuits to []."""
    monkeypatch.setattr(sr, "_YARA_AVAILABLE", False)

    _write_manifest(
        tmp_path,
        "name: yara_unavailable\n"
        "tier: synthetic\n"
        "fixtures:\n"
        "  yara_rules: rules\n"
        "  yara_scan_dir: samples\n"
        "expected:\n"
        "  malicious_executables: []\n",
    )
    (tmp_path / "rules").mkdir()
    (tmp_path / "samples").mkdir()
    (tmp_path / "rules" / "r.yar").write_text("rule t { condition: false }")
    (tmp_path / "samples" / "b.bin").write_bytes(b"benign")

    manifest = load_scenario(tmp_path)
    report = run_scenario(manifest)

    # has_yara is True so the scenario does not skip, but _run_yara returns [].
    assert report.skipped is False, report.skip_reason
    assert report.findings_count == 0


def test_run_yara_compile_failure_returns_empty(tmp_path: Path, monkeypatch) -> None:
    """A compile failure (FileNotFoundError/ValueError/MissingYaraError) makes
    _run_yara return [] rather than propagate."""
    if not sr._YARA_AVAILABLE:
        pytest.skip("yara-python not installed; compile path not reachable")

    def _boom(_rules_dir):
        raise FileNotFoundError("no rules here")

    monkeypatch.setattr(sr.YaraScanner, "compile_from_directory", staticmethod(_boom))

    _write_manifest(
        tmp_path,
        "name: yara_compile_fail\n"
        "tier: synthetic\n"
        "fixtures:\n"
        "  yara_rules: rules\n"
        "  yara_scan_dir: samples\n"
        "expected:\n"
        "  malicious_executables: []\n",
    )
    (tmp_path / "rules").mkdir()
    (tmp_path / "samples").mkdir()

    manifest = load_scenario(tmp_path)
    report = run_scenario(manifest)

    assert report.skipped is False, report.skip_reason
    assert report.findings_count == 0


# ---------------------------------------------------------------------------
# evidence-image dispatch through detect_from_image (lines 409-413, 424)
# ---------------------------------------------------------------------------


def _evidence_manifest(tmp_path: Path, kind: str) -> Path:
    _write_manifest(
        tmp_path,
        "name: evidence_dispatch\n"
        "tier: real\n"
        "evidence:\n"
        "  - path: image.dd\n"
        f"    kind: {kind}\n"
        "expected:\n"
        "  malicious_executables: []\n",
    )
    (tmp_path / "image.dd").write_bytes(b"\x00" * 512)
    return tmp_path


def test_evidence_raw_dispatch_appends_finding(tmp_path: Path, monkeypatch) -> None:
    """A raw image whose detect_from_image returns a finding flows through the
    dispatch loop (append + dispatched_kinds) into _score."""
    captured: dict = {}

    class _FakeFinding:
        # Mirrors the minimal Finding shape _score touches.
        evidence: dict = {}
        confidence = 0.9

    sentinel = _FakeFinding()

    def _fake_detect(path: Path):
        captured["path"] = path
        return sentinel

    monkeypatch.setattr(sr, "detect_from_image", _fake_detect)

    manifest = load_scenario(_evidence_manifest(tmp_path, "raw"))
    report = run_scenario(manifest)

    assert report.skipped is False, report.skip_reason
    assert report.findings_count == 1
    assert report.findings == [sentinel]
    assert captured["path"].name == "image.dd"


@pytest.mark.parametrize("kind", ["e01", "dd"])
def test_evidence_e01_and_dd_dispatch_with_no_finding(
    tmp_path: Path, monkeypatch, kind: str
) -> None:
    """e01/dd kinds dispatch; when detect_from_image returns None the finding
    is not appended but the kind is still marked dispatched so _score runs."""
    monkeypatch.setattr(sr, "detect_from_image", lambda _p: None)

    manifest = load_scenario(_evidence_manifest(tmp_path, kind))
    report = run_scenario(manifest)

    assert report.skipped is False, report.skip_reason
    assert report.findings_count == 0
    # Reached _score (not the no-dispatchable-kind skip).
    assert "dispatchable" not in report.skip_reason
