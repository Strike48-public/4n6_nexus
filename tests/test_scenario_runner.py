"""Tests for the scenario runner used by `python -m sift_find_evil run --scenario`."""

from __future__ import annotations

from pathlib import Path

import pytest

from sift_find_evil.scenario_runner import (
    ScenarioLoadError,
    load_scenario,
    run_scenario_path,
)


REPO_ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def synthetic_ransomware_dir() -> Path:
    return REPO_ROOT / "scenarios" / "synthetic" / "02_ransomware"


@pytest.fixture
def synthetic_clean_dir() -> Path:
    return REPO_ROOT / "scenarios" / "synthetic" / "01_clean_baseline"


@pytest.fixture
def real_nitroba_dir() -> Path:
    return REPO_ROOT / "scenarios" / "real" / "nitroba"


def test_load_scenario_parses_manifest(synthetic_ransomware_dir: Path) -> None:
    manifest = load_scenario(synthetic_ransomware_dir)

    assert manifest.name == "02_ransomware"
    assert manifest.tier == "synthetic"
    assert manifest.directory == synthetic_ransomware_dir
    assert manifest.fixtures["mft"] == "mft.csv"
    assert "ransom_note.exe" in manifest.expected_malicious_executables
    assert manifest.expected_finding_counts["total"] == 3


def test_load_scenario_accepts_yaml_path(synthetic_ransomware_dir: Path) -> None:
    manifest = load_scenario(synthetic_ransomware_dir / "scenario.yaml")

    assert manifest.name == "02_ransomware"


def test_load_scenario_missing_manifest_raises(tmp_path: Path) -> None:
    with pytest.raises(ScenarioLoadError):
        load_scenario(tmp_path)


def test_run_synthetic_ransomware_passes_expectations(
    synthetic_ransomware_dir: Path,
) -> None:
    report = run_scenario_path(synthetic_ransomware_dir)

    assert report.manifest.name == "02_ransomware"
    assert report.passed is True
    assert report.precision == 1.0
    assert report.recall == 1.0
    assert not report.false_positives
    assert not report.false_negatives
    assert report.findings_count >= 3


def test_run_synthetic_clean_baseline_produces_no_findings(
    synthetic_clean_dir: Path,
) -> None:
    report = run_scenario_path(synthetic_clean_dir)

    assert report.passed is True
    assert report.findings_count == 0


def test_run_real_tier_without_evidence_skips_cleanly(real_nitroba_dir: Path) -> None:
    report = run_scenario_path(real_nitroba_dir)

    assert report.manifest.tier == "real"
    assert report.skipped is True
    assert "evidence" in report.skip_reason.lower()
    assert report.passed is True


def test_run_scenario_path_returns_serializable_report(
    synthetic_ransomware_dir: Path,
) -> None:
    report = run_scenario_path(synthetic_ransomware_dir)

    payload = report.to_dict()

    assert payload["name"] == "02_ransomware"
    assert payload["passed"] is True
    assert "precision" in payload
    assert "findings_count" in payload


def _write_manifest(tmp_path: Path, body: str) -> Path:
    (tmp_path / "scenario.yaml").write_text(body, encoding="utf-8")
    return tmp_path


def test_load_scenario_rejects_fixture_path_traversal(tmp_path: Path) -> None:
    _write_manifest(
        tmp_path,
        "name: escape\n"
        "tier: synthetic\n"
        "fixtures:\n"
        "  mft: ../../../etc/passwd\n",
    )

    with pytest.raises(ScenarioLoadError, match="escapes scenario directory"):
        load_scenario(tmp_path)


def test_load_scenario_rejects_evidence_path_traversal(tmp_path: Path) -> None:
    _write_manifest(
        tmp_path,
        "name: escape\n"
        "tier: real\n"
        "evidence:\n"
        "  - path: ../../../etc/shadow\n"
        "    kind: raw\n",
    )

    with pytest.raises(ScenarioLoadError, match="escapes scenario directory"):
        load_scenario(tmp_path)


def test_load_scenario_rejects_oversized_manifest(tmp_path: Path) -> None:
    from sift_find_evil.scenario_runner import MAX_MANIFEST_SIZE

    padding = "x" * (MAX_MANIFEST_SIZE + 1)
    _write_manifest(tmp_path, f"name: big\ntier: synthetic\nnotes: |\n  {padding}\n")

    with pytest.raises(ScenarioLoadError, match="max"):
        load_scenario(tmp_path)


def test_load_scenario_rejects_non_string_malicious_list(tmp_path: Path) -> None:
    _write_manifest(
        tmp_path,
        "name: bad\n"
        "tier: synthetic\n"
        "expected:\n"
        "  malicious_executables:\n"
        "    - name: not_a_string\n",
    )

    with pytest.raises(ScenarioLoadError, match="list of strings"):
        load_scenario(tmp_path)


def test_load_scenario_rejects_non_numeric_min_precision(tmp_path: Path) -> None:
    _write_manifest(
        tmp_path,
        "name: bad\n" "tier: synthetic\n" "expected:\n" "  min_precision: high\n",
    )

    with pytest.raises(ScenarioLoadError, match="must be numeric"):
        load_scenario(tmp_path)


def test_load_scenario_rejects_fixture_with_non_string_value(tmp_path: Path) -> None:
    _write_manifest(
        tmp_path,
        "name: bad\n"
        "tier: synthetic\n"
        "fixtures:\n"
        "  mft:\n"
        "    nested: value\n",
    )

    with pytest.raises(ScenarioLoadError, match="must be a string path"):
        load_scenario(tmp_path)


# ---------------------------------------------------------------------------
# YARA-only scenario dispatch (SFE-yzb)
# ---------------------------------------------------------------------------


yara = pytest.importorskip("yara")  # skips YARA tests on hosts without libyara


@pytest.fixture
def synthetic_yara_dir() -> Path:
    return REPO_ROOT / "scenarios" / "synthetic" / "11_yara_malware"


def test_run_yara_only_scenario_passes(synthetic_yara_dir: Path) -> None:
    """A scenario with only yara_rules + yara_scan_dir should dispatch YaraDetector."""
    report = run_scenario_path(synthetic_yara_dir)

    assert report.skipped is False, report.skip_reason
    assert report.passed is True
    assert report.precision == 1.0
    assert report.recall == 1.0
    assert report.findings_count == 1
    assert "yara_match" in report.true_positives


def test_yara_only_scenario_loads_fixtures(synthetic_yara_dir: Path) -> None:
    manifest = load_scenario(synthetic_yara_dir)

    assert manifest.fixtures.get("yara_rules") == "yara_rules"
    assert manifest.fixtures.get("yara_scan_dir") == "samples"
    # YARA-only scenarios do not declare the causality triplet.
    assert "mft" not in manifest.fixtures
    assert "prefetch" not in manifest.fixtures
    assert "evtx" not in manifest.fixtures
