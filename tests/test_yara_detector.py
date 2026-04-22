"""Unit tests for YaraDetector.

yara-python is optional. Tests skip gracefully on hosts without libyara.
"""

from __future__ import annotations

from pathlib import Path

import pytest

yara = pytest.importorskip("yara")

from sift_find_evil.detectors.yara_detector import YaraDetector  # noqa: E402
from sift_find_evil.findings import FindingCategory  # noqa: E402
from sift_find_evil.yara_scan.scanner import YaraScanner  # noqa: E402


# -- rule source helpers --------------------------------------------------

_MZ_HIGH_RULE = """
rule mz_header_high {
    meta:
        description = "MZ header, severity=high for testing"
        severity = "high"
        mitre_attack = "T1055"
    strings:
        $mz = "MZ"
    condition:
        $mz at 0
}
"""

_UPX_MEDIUM_RULE = """
rule upx_medium {
    meta:
        description = "UPX sections, severity=medium"
        severity = "medium"
        family = "upx_packer"
    strings:
        $upx0 = "UPX0"
        $upx1 = "UPX1"
    condition:
        any of them
}
"""

_BENIGN_LOW_RULE = """
rule benign_low {
    meta:
        description = "Harmless marker, severity=low"
        severity = "low"
    strings:
        $m = "BENIGN"
    condition:
        $m
}
"""

_NO_SEVERITY_RULE = """
rule no_severity_meta {
    meta:
        description = "Rule without severity field — detector should default."
    strings:
        $m = "NOSEV"
    condition:
        $m
}
"""


# -- fixtures --------------------------------------------------------------


@pytest.fixture
def scanner_high(tmp_path: Path) -> YaraScanner:
    (tmp_path / "mz_high.yar").write_text(_MZ_HIGH_RULE)
    return YaraScanner.compile_from_directory(tmp_path)


@pytest.fixture
def scanner_multi(tmp_path: Path) -> YaraScanner:
    (tmp_path / "mz.yar").write_text(_MZ_HIGH_RULE)
    (tmp_path / "upx.yar").write_text(_UPX_MEDIUM_RULE)
    (tmp_path / "benign.yar").write_text(_BENIGN_LOW_RULE)
    return YaraScanner.compile_from_directory(tmp_path)


@pytest.fixture
def scanner_no_sev(tmp_path: Path) -> YaraScanner:
    (tmp_path / "nosev.yar").write_text(_NO_SEVERITY_RULE)
    return YaraScanner.compile_from_directory(tmp_path)


@pytest.fixture
def mz_file(tmp_path: Path) -> Path:
    p = tmp_path / "sample.bin"
    p.write_bytes(b"MZ\x90\x00\x03")
    return p


@pytest.fixture
def upx_file(tmp_path: Path) -> Path:
    p = tmp_path / "packed.bin"
    p.write_bytes(b"\x00UPX0\x00stuff\x00UPX1\x00")
    return p


@pytest.fixture
def both_file(tmp_path: Path) -> Path:
    p = tmp_path / "both.bin"
    p.write_bytes(b"MZ\x90\x00UPX0\x00UPX1\x00")
    return p


@pytest.fixture
def clean_file(tmp_path: Path) -> Path:
    p = tmp_path / "clean.txt"
    p.write_text("nothing to see")
    return p


@pytest.fixture
def nosev_file(tmp_path: Path) -> Path:
    p = tmp_path / "nosev.bin"
    p.write_bytes(b"something NOSEV payload")
    return p


# -- single-file detection -------------------------------------------------


def test_single_match_emits_one_finding(
    scanner_high: YaraScanner, mz_file: Path
) -> None:
    detector = YaraDetector(scanner=scanner_high)
    findings = detector.analyze_file(mz_file)
    assert len(findings) == 1
    f = findings[0]
    assert f.category == FindingCategory.MALWARE_CLASSIFICATION
    assert "mz_header_high" in f.title
    assert f.evidence["rule"] == "mz_header_high"
    assert f.evidence["source_file"] == str(mz_file)


def test_no_match_returns_empty(scanner_high: YaraScanner, clean_file: Path) -> None:
    detector = YaraDetector(scanner=scanner_high)
    assert detector.analyze_file(clean_file) == []


def test_multiple_rules_emit_multiple_findings(
    scanner_multi: YaraScanner, both_file: Path
) -> None:
    detector = YaraDetector(scanner=scanner_multi)
    findings = detector.analyze_file(both_file)
    rules = {f.evidence["rule"] for f in findings}
    assert {"mz_header_high", "upx_medium"}.issubset(rules)


# -- confidence model ------------------------------------------------------


def test_high_severity_confidence(scanner_high: YaraScanner, mz_file: Path) -> None:
    detector = YaraDetector(scanner=scanner_high)
    f = detector.analyze_file(mz_file)[0]
    # Base HIGH 0.90 + mitre_attack bonus 0.05 (no family on this rule).
    assert f.confidence == pytest.approx(0.95, abs=0.001)
    assert f.severity == "high"


def test_medium_severity_confidence(scanner_multi: YaraScanner, upx_file: Path) -> None:
    detector = YaraDetector(scanner=scanner_multi)
    findings = detector.analyze_file(upx_file)
    upx = next(f for f in findings if f.evidence["rule"] == "upx_medium")
    # Base MEDIUM severity = 0.70. family bonus is +0.05 (known packer marker).
    assert upx.confidence == pytest.approx(0.75, abs=0.001)
    assert upx.severity == "medium"


def test_low_severity_confidence(
    tmp_path: Path,
) -> None:
    (tmp_path / "benign.yar").write_text(_BENIGN_LOW_RULE)
    scanner = YaraScanner.compile_from_directory(tmp_path)
    target = tmp_path / "file.bin"
    target.write_bytes(b"here is a BENIGN token")
    detector = YaraDetector(scanner=scanner)
    f = detector.analyze_file(target)[0]
    assert f.confidence == pytest.approx(0.50, abs=0.001)
    assert f.severity == "low"


def test_missing_severity_defaults_to_medium(
    scanner_no_sev: YaraScanner, nosev_file: Path
) -> None:
    detector = YaraDetector(scanner=scanner_no_sev)
    f = detector.analyze_file(nosev_file)[0]
    assert f.severity == "medium"
    assert f.confidence == pytest.approx(0.70, abs=0.001)


def test_confidence_is_capped(tmp_path: Path) -> None:
    """Synthetic rule carrying every bonus still caps at 0.95."""
    rule = """
rule capped {
    meta:
        severity = "high"
        family = "known_family"
        mitre_attack = "T1055"
    strings:
        $m = "CAP"
    condition:
        $m
}
"""
    (tmp_path / "capped.yar").write_text(rule)
    scanner = YaraScanner.compile_from_directory(tmp_path)
    target = tmp_path / "t.bin"
    target.write_bytes(b"CAP payload")
    detector = YaraDetector(scanner=scanner)
    f = detector.analyze_file(target)[0]
    assert f.confidence <= 0.95


# -- evidence payload ------------------------------------------------------


def test_evidence_carries_match_offsets_and_strings(
    scanner_high: YaraScanner, mz_file: Path
) -> None:
    detector = YaraDetector(scanner=scanner_high)
    f = detector.analyze_file(mz_file)[0]
    strings = f.evidence["matching_strings"]
    assert isinstance(strings, list)
    assert strings
    first = strings[0]
    assert "identifier" in first
    assert "offset" in first
    assert first["offset"] == 0


def test_evidence_carries_rule_metadata(
    scanner_high: YaraScanner, mz_file: Path
) -> None:
    detector = YaraDetector(scanner=scanner_high)
    f = detector.analyze_file(mz_file)[0]
    meta = f.evidence["rule_meta"]
    assert meta["severity"] == "high"
    assert meta["mitre_attack"] == "T1055"


def test_evidence_includes_mitre_attack(
    scanner_high: YaraScanner, mz_file: Path
) -> None:
    detector = YaraDetector(scanner=scanner_high)
    f = detector.analyze_file(mz_file)[0]
    assert "T1055" in (f.evidence.get("mitre_attack") or [])


# -- directory scanning ----------------------------------------------------


def test_analyze_directory_returns_findings_for_all_matches(
    scanner_multi: YaraScanner, tmp_path: Path
) -> None:
    targets = tmp_path / "targets"
    targets.mkdir()
    (targets / "a.bin").write_bytes(b"MZ\x90\x00")
    (targets / "b.bin").write_bytes(b"\x00UPX0\x00UPX1\x00")
    (targets / "c.txt").write_text("clean")
    detector = YaraDetector(scanner=scanner_multi)
    findings = detector.analyze_directory(targets)
    rules = [f.evidence["rule"] for f in findings]
    assert rules.count("mz_header_high") == 1
    assert rules.count("upx_medium") == 1


def test_analyze_directory_nonexistent_raises(
    scanner_high: YaraScanner, tmp_path: Path
) -> None:
    detector = YaraDetector(scanner=scanner_high)
    with pytest.raises(FileNotFoundError):
        detector.analyze_directory(tmp_path / "missing")


def test_analyze_file_nonexistent_raises(
    scanner_high: YaraScanner, tmp_path: Path
) -> None:
    detector = YaraDetector(scanner=scanner_high)
    with pytest.raises(FileNotFoundError):
        detector.analyze_file(tmp_path / "missing.bin")


# -- top-N limit -----------------------------------------------------------


def test_invalid_max_findings_raises(scanner_high: YaraScanner) -> None:
    with pytest.raises(ValueError, match="must be positive"):
        YaraDetector(scanner=scanner_high, max_findings_per_file=0)
    with pytest.raises(ValueError, match="must be positive"):
        YaraDetector(scanner=scanner_high, max_findings_per_file=-5)


def test_instance_count_cap_on_noisy_rule(tmp_path: Path) -> None:
    """A rule firing many times on one file caps string instances but keeps match_count."""
    rule = """
rule many_hits {
    meta:
        severity = "medium"
    strings:
        $a = "AB"
    condition:
        $a
}
"""
    (tmp_path / "noisy.yar").write_text(rule)
    scanner = YaraScanner.compile_from_directory(tmp_path)
    target = tmp_path / "noisy.bin"
    # 100 "AB" hits — above the 50-instance cap.
    target.write_bytes(b"AB" * 100)
    detector = YaraDetector(scanner=scanner)
    f = detector.analyze_file(target)[0]
    assert f.evidence["match_count"] == 100
    assert f.evidence["instances_captured"] == 50
    assert f.evidence["instances_truncated"] is True
    assert len(f.evidence["matching_strings"]) == 50


def test_max_findings_per_file_limit(tmp_path: Path) -> None:
    """When the same file triggers many rules, cap to top-N by confidence."""
    (tmp_path / "mz.yar").write_text(_MZ_HIGH_RULE)
    (tmp_path / "upx.yar").write_text(_UPX_MEDIUM_RULE)
    (tmp_path / "benign.yar").write_text(_BENIGN_LOW_RULE)
    scanner = YaraScanner.compile_from_directory(tmp_path)
    target = tmp_path / "triple.bin"
    target.write_bytes(b"MZ\x90\x00UPX0\x00UPX1\x00BENIGN")
    detector = YaraDetector(scanner=scanner, max_findings_per_file=2)
    findings = detector.analyze_file(target)
    assert len(findings) == 2
    # Top 2 are HIGH + MEDIUM, LOW dropped.
    rules = {f.evidence["rule"] for f in findings}
    assert "benign_low" not in rules
