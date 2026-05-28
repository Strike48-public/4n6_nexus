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


def test_load_scenario_rejects_non_dict_top_level(tmp_path: Path) -> None:
    """Test load_scenario rejects non-dict top-level YAML."""
    (tmp_path / "scenario.yaml").write_text("- item1\n- item2\n", encoding="utf-8")

    with pytest.raises(ScenarioLoadError, match="top-level must be a mapping"):
        load_scenario(tmp_path)


def test_load_scenario_rejects_non_dict_fixtures(tmp_path: Path) -> None:
    """Test load_scenario rejects non-dict fixtures."""
    _write_manifest(
        tmp_path,
        "name: bad\n"
        "tier: synthetic\n"
        "fixtures:\n"
        "  - mft.csv\n",
    )

    with pytest.raises(ScenarioLoadError, match="'fixtures' must be a mapping"):
        load_scenario(tmp_path)


def test_load_scenario_skips_empty_fixture_values(tmp_path: Path) -> None:
    """Test load_scenario skips fixtures with null/empty values."""
    _write_manifest(
        tmp_path,
        "name: test\n"
        "tier: synthetic\n"
        "fixtures:\n"
        "  mft: mft.csv\n"
        "  prefetch: null\n"
        "  evtx: ''\n",
    )

    manifest = load_scenario(tmp_path)
    assert "mft" in manifest.fixtures
    assert "prefetch" not in manifest.fixtures
    assert "evtx" not in manifest.fixtures


def test_load_scenario_rejects_non_list_evidence(tmp_path: Path) -> None:
    """Test load_scenario rejects non-list evidence."""
    _write_manifest(
        tmp_path,
        "name: bad\n"
        "tier: real\n"
        "evidence:\n"
        "  path: disk.dd\n",
    )

    with pytest.raises(ScenarioLoadError, match="'evidence' must be a list"):
        load_scenario(tmp_path)


def test_load_scenario_skips_non_dict_evidence_entries(tmp_path: Path) -> None:
    """Test load_scenario skips non-dict evidence entries."""
    _write_manifest(
        tmp_path,
        "name: test\n"
        "tier: real\n"
        "evidence:\n"
        "  - disk.dd\n"
        "  - path: valid.dd\n"
        "    kind: raw\n",
    )

    manifest = load_scenario(tmp_path)
    assert len(manifest.evidence) == 1
    assert manifest.evidence[0]["path"] == "valid.dd"


def test_load_scenario_rejects_evidence_entry_missing_path(tmp_path: Path) -> None:
    """Test load_scenario rejects evidence entry missing path."""
    _write_manifest(
        tmp_path,
        "name: bad\n"
        "tier: real\n"
        "evidence:\n"
        "  - kind: raw\n",
    )

    with pytest.raises(ScenarioLoadError, match="evidence entry missing string 'path'"):
        load_scenario(tmp_path)


def test_load_scenario_rejects_evidence_entry_empty_path(tmp_path: Path) -> None:
    """Test load_scenario rejects evidence entry with empty path."""
    _write_manifest(
        tmp_path,
        "name: bad\n"
        "tier: real\n"
        "evidence:\n"
        "  - path: ''\n"
        "    kind: raw\n",
    )

    with pytest.raises(ScenarioLoadError, match="evidence entry missing string 'path'"):
        load_scenario(tmp_path)


def test_load_scenario_rejects_non_dict_finding_counts(tmp_path: Path) -> None:
    """Test load_scenario rejects non-dict finding_counts."""
    _write_manifest(
        tmp_path,
        "name: bad\n"
        "tier: synthetic\n"
        "expected:\n"
        "  finding_counts:\n"
        "    - total: 5\n",
    )

    with pytest.raises(ScenarioLoadError, match="expected.finding_counts must be a mapping"):
        load_scenario(tmp_path)


def test_load_scenario_rejects_non_integer_finding_count_values(tmp_path: Path) -> None:
    """Test load_scenario rejects non-integer finding_counts values."""
    _write_manifest(
        tmp_path,
        "name: bad\n"
        "tier: synthetic\n"
        "expected:\n"
        "  finding_counts:\n"
        "    total: five\n",
    )

    with pytest.raises(ScenarioLoadError, match="finding_counts values must be integers"):
        load_scenario(tmp_path)


def test_load_scenario_rejects_non_numeric_min_recall(tmp_path: Path) -> None:
    """Test load_scenario rejects non-numeric min_recall."""
    _write_manifest(
        tmp_path,
        "name: bad\n"
        "tier: synthetic\n"
        "expected:\n"
        "  min_recall: high\n",
    )

    with pytest.raises(ScenarioLoadError, match="must be numeric"):
        load_scenario(tmp_path)


# ---------------------------------------------------------------------------
# Scenario Validation Edge Cases
# ---------------------------------------------------------------------------


def test_run_scenario_with_neither_fixtures_nor_evidence_skips_gracefully(
    tmp_path: Path,
) -> None:
    """Scenario with neither fixtures nor evidence skips with clear reason."""
    # Arrange
    _write_manifest(
        tmp_path,
        "name: empty\n"
        "tier: synthetic\n"
        "description: Test scenario with no data\n",
    )

    # Act
    from sift_find_evil.scenario_runner import run_scenario

    manifest = load_scenario(tmp_path)
    report = run_scenario(manifest)

    # Assert
    assert report.skipped is True
    assert "neither fixtures nor evidence" in report.skip_reason.lower()


def test_run_scenario_with_missing_causality_fixtures_skips(tmp_path: Path) -> None:
    """Scenario missing required causality fixtures (mft/prefetch/evtx) skips."""
    # Arrange
    _write_manifest(
        tmp_path,
        "name: incomplete\n"
        "tier: synthetic\n"
        "fixtures:\n"
        "  mft: mft.csv\n"
        "  # Missing prefetch and evtx\n",
    )

    # Act
    from sift_find_evil.scenario_runner import run_scenario

    manifest = load_scenario(tmp_path)
    report = run_scenario(manifest)

    # Assert
    assert report.skipped is True
    assert "missing required mft/prefetch/evtx" in report.skip_reason.lower()


def test_run_evidence_scenario_missing_required_evidence_file_skips(
    tmp_path: Path,
) -> None:
    """Evidence scenario with missing required file skips gracefully."""
    # Arrange
    _write_manifest(
        tmp_path,
        "name: missing_evidence\n"
        "tier: real\n"
        "evidence:\n"
        "  - path: disk.dd\n"
        "    kind: raw\n"
        "    required: true\n",
    )

    # Act
    from sift_find_evil.scenario_runner import run_scenario

    manifest = load_scenario(tmp_path)
    report = run_scenario(manifest)

    # Assert
    assert report.skipped is True
    assert "missing required evidence" in report.skip_reason.lower()


def test_run_evidence_scenario_no_dispatchable_kind_skips_with_warning(
    tmp_path: Path,
) -> None:
    """Evidence scenario with unsupported evidence kind skips."""
    # Arrange
    _write_manifest(
        tmp_path,
        "name: unsupported\n"
        "tier: real\n"
        "evidence:\n"
        "  - path: capture.pcap\n"
        "    kind: pcap\n",
    )
    (tmp_path / "capture.pcap").write_bytes(b"fake pcap data")

    # Act
    from sift_find_evil.scenario_runner import run_scenario

    manifest = load_scenario(tmp_path)
    report = run_scenario(manifest)

    # Assert
    assert report.skipped is True
    assert "no dispatchable kind" in report.skip_reason.lower()


def test_run_evidence_scenario_no_files_present_skips(tmp_path: Path) -> None:
    """Evidence scenario with no files on disk skips gracefully."""
    # Arrange
    _write_manifest(
        tmp_path,
        "name: no_files\n"
        "tier: real\n"
        "evidence:\n"
        "  - path: disk.dd\n"
        "    kind: raw\n",
    )

    # Act
    from sift_find_evil.scenario_runner import run_scenario

    manifest = load_scenario(tmp_path)
    report = run_scenario(manifest)

    # Assert
    assert report.skipped is True
    assert "no evidence files present" in report.skip_reason.lower()


# ---------------------------------------------------------------------------
# Scoring Edge Cases
# ---------------------------------------------------------------------------


def test_score_webmail_exfiltration_counting_with_zero_events(tmp_path: Path) -> None:
    """Scoring correctly handles zero webmail exfiltration events."""
    # Arrange
    _write_manifest(
        tmp_path,
        "name: test_webmail\n"
        "tier: synthetic\n"
        "fixtures:\n"
        "  mft: mft.csv\n"
        "  prefetch: prefetch.csv\n"
        "  evtx: evtx.csv\n"
        "expected:\n"
        "  finding_counts:\n"
        "    webmail_exfiltration: 2\n",
    )

    # Create minimal valid fixture files with proper schemas
    (tmp_path / "mft.csv").write_text(
        "EntryNumber,FileName,ParentPath,Created0x10\n"
        "1,test.exe,C:\\\\Users,2024-01-01T00:00:00Z\n"
    )
    (tmp_path / "prefetch.csv").write_text(
        "SourceFilename,Executable,RunCount,LastRunTime\n"
        "TEST.EXE-ABCD1234.pf,TEST.EXE,1,2024-01-01T00:00:00Z\n"
    )
    (tmp_path / "evtx.csv").write_text(
        "TimeCreated,EventId,RecordId,Computer,PayloadData1\n"
        "2024-01-01T00:00:00Z,4688,1,TEST-PC,C:\\\\Users\\\\test.exe\n"
    )

    # Act
    from sift_find_evil.scenario_runner import run_scenario

    manifest = load_scenario(tmp_path)
    report = run_scenario(manifest)

    # Assert
    assert report.passed is False
    assert "webmail_exfiltration" in report.false_negatives
    assert report.false_negatives.count("webmail_exfiltration") == 2


def test_score_cloud_upload_counting_with_zero_events(tmp_path: Path) -> None:
    """Scoring correctly handles zero cloud upload events."""
    # Arrange
    _write_manifest(
        tmp_path,
        "name: test_cloud\n"
        "tier: synthetic\n"
        "fixtures:\n"
        "  mft: mft.csv\n"
        "  prefetch: prefetch.csv\n"
        "  evtx: evtx.csv\n"
        "expected:\n"
        "  finding_counts:\n"
        "    cloud_upload: 1\n",
    )

    # Create minimal valid fixture files with proper schemas
    (tmp_path / "mft.csv").write_text(
        "EntryNumber,FileName,ParentPath,Created0x10\n"
        "1,test.exe,C:\\\\Users,2024-01-01T00:00:00Z\n"
    )
    (tmp_path / "prefetch.csv").write_text(
        "SourceFilename,Executable,RunCount,LastRunTime\n"
        "TEST.EXE-ABCD1234.pf,TEST.EXE,1,2024-01-01T00:00:00Z\n"
    )
    (tmp_path / "evtx.csv").write_text(
        "TimeCreated,EventId,RecordId,Computer,PayloadData1\n"
        "2024-01-01T00:00:00Z,4688,1,TEST-PC,C:\\\\Users\\\\test.exe\n"
    )

    # Act
    from sift_find_evil.scenario_runner import run_scenario

    manifest = load_scenario(tmp_path)
    report = run_scenario(manifest)

    # Assert
    assert report.passed is False
    assert "cloud_upload" in report.false_negatives
    assert report.false_negatives.count("cloud_upload") == 1


def test_score_yara_match_counting_with_zero_matches(tmp_path: Path) -> None:
    """Scoring correctly handles zero YARA matches."""
    # Arrange
    _write_manifest(
        tmp_path,
        "name: test_yara\n"
        "tier: synthetic\n"
        "fixtures:\n"
        "  yara_rules: rules\n"
        "  yara_scan_dir: samples\n"
        "expected:\n"
        "  finding_counts:\n"
        "    yara_match: 1\n",
    )

    # Create empty directories
    (tmp_path / "rules").mkdir()
    (tmp_path / "samples").mkdir()
    (tmp_path / "rules" / "test.yar").write_text(
        "rule test { condition: false }"
    )
    (tmp_path / "samples" / "benign.exe").write_bytes(b"benign content")

    # Act
    from sift_find_evil.scenario_runner import run_scenario

    manifest = load_scenario(tmp_path)
    report = run_scenario(manifest)

    # Assert
    assert report.passed is False
    assert "yara_match" in report.false_negatives


def test_load_scenario_with_empty_expected_block_uses_defaults(tmp_path: Path) -> None:
    """Scenario with empty expected block uses default 1.0 precision/recall."""
    # Arrange
    _write_manifest(
        tmp_path,
        "name: defaults\n"
        "tier: synthetic\n"
        "expected: {}\n",
    )

    # Act
    manifest = load_scenario(tmp_path)

    # Assert
    assert manifest.min_precision == 1.0
    assert manifest.min_recall == 1.0
    assert len(manifest.expected_malicious_executables) == 0
    assert len(manifest.expected_finding_counts) == 0


def test_load_scenario_with_null_expected_uses_defaults(tmp_path: Path) -> None:
    """Scenario with null expected block uses default values."""
    # Arrange
    _write_manifest(
        tmp_path,
        "name: null_expected\n"
        "tier: synthetic\n"
        "expected: null\n",
    )

    # Act
    manifest = load_scenario(tmp_path)

    # Assert
    assert manifest.min_precision == 1.0
    assert manifest.min_recall == 1.0


def test_scenario_report_precision_with_zero_detections_returns_one(
    synthetic_clean_dir: Path,
) -> None:
    """ScenarioReport.precision returns 1.0 when no detections and none expected."""
    # Arrange
    report = run_scenario_path(synthetic_clean_dir)

    # Act
    precision = report.precision

    # Assert
    assert precision == 1.0
    assert len(report.true_positives) == 0
    assert len(report.false_positives) == 0


def test_scenario_report_recall_with_zero_expectations_returns_one(
    synthetic_clean_dir: Path,
) -> None:
    """ScenarioReport.recall returns 1.0 when no findings expected."""
    # Arrange
    report = run_scenario_path(synthetic_clean_dir)

    # Act
    recall = report.recall

    # Assert
    assert recall == 1.0
    assert len(report.true_positives) == 0
    assert len(report.false_negatives) == 0


def test_scenario_report_f1_score_with_zero_values_returns_zero() -> None:
    """ScenarioReport.f1 returns 0.0 when precision and recall are both 0."""
    # Arrange
    from sift_find_evil.scenario_runner import ScenarioReport, ScenarioManifest

    manifest = ScenarioManifest(
        name="test",
        tier="synthetic",
        directory=Path("/tmp"),
        description="",
        fixtures={},
        evidence=[],
        expected_malicious_executables=frozenset(["malware.exe"]),
        expected_finding_counts={},
        min_precision=1.0,
        min_recall=1.0,
    )

    report = ScenarioReport(
        manifest=manifest,
        findings_count=0,
        detected_executables=[],
        false_negatives=["malware.exe"],
    )

    # Act
    f1 = report.f1

    # Assert
    assert f1 == 0.0
