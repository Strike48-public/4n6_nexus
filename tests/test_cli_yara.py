"""CLI wiring tests for --yara-rules / --yara-scan dispatch (SFE-yzb)."""

from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("yara")  # skip the whole module on hosts without libyara

from sift_find_evil.cli import _run_yara_detector


REPO_ROOT = Path(__file__).resolve().parent.parent
YARA_SCENARIO = REPO_ROOT / "scenarios" / "synthetic" / "11_yara_malware"


def test_run_yara_detector_returns_empty_when_paths_none() -> None:
    assert _run_yara_detector(None, None, verbose=False) == []


def test_run_yara_detector_returns_empty_when_one_path_none() -> None:
    """Mixed-None inputs are a guard path; cmd_analyze validates paired flags
    upstream, so the helper's job is to noop rather than raise."""
    assert _run_yara_detector(YARA_SCENARIO / "yara_rules", None, verbose=False) == []
    assert _run_yara_detector(None, YARA_SCENARIO / "samples", verbose=False) == []


def test_run_yara_detector_scans_directory() -> None:
    findings = _run_yara_detector(
        YARA_SCENARIO / "yara_rules",
        YARA_SCENARIO / "samples",
        verbose=False,
    )
    assert len(findings) == 1
    assert findings[0].category.value == "malware_classification"
    assert findings[0].evidence["rule"] == "eicar_test_string"


def test_run_yara_detector_scans_single_file() -> None:
    findings = _run_yara_detector(
        YARA_SCENARIO / "yara_rules",
        YARA_SCENARIO / "samples" / "suspect.txt",
        verbose=False,
    )
    assert len(findings) == 1
    assert findings[0].evidence["rule"] == "eicar_test_string"


def test_run_yara_detector_clean_file_has_no_findings() -> None:
    findings = _run_yara_detector(
        YARA_SCENARIO / "yara_rules",
        YARA_SCENARIO / "samples" / "clean.txt",
        verbose=False,
    )
    assert findings == []
