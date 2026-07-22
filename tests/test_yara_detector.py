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


def test_severity_non_string_defaults_to_medium(tmp_path: Path) -> None:
    """Test _severity_from_meta returns default when severity is not a string."""
    rule_source = """
rule non_string_severity {
    meta:
        severity = 42
    strings:
        $test = "TEST"
    condition:
        $test
}
"""
    rule_file = tmp_path / "non_string.yara"
    rule_file.write_text(rule_source)

    scanner = YaraScanner.compile_from_directory(rule_file.parent)

    test_file = tmp_path / "test.bin"
    test_file.write_bytes(b"TEST")

    detector = YaraDetector(scanner=scanner)
    findings = detector.analyze_file(test_file)
    assert findings
    assert findings[0].severity == "medium"


def test_severity_invalid_string_defaults_to_medium(tmp_path: Path) -> None:
    """Test _severity_from_meta returns default when severity is invalid string."""
    rule_source = """
rule invalid_severity {
    meta:
        severity = "INVALID"
    strings:
        $test = "TEST"
    condition:
        $test
}
"""
    rule_file = tmp_path / "invalid_severity.yara"
    rule_file.write_text(rule_source)

    scanner = YaraScanner.compile_from_directory(rule_file.parent)

    test_file = tmp_path / "test.bin"
    test_file.write_bytes(b"TEST")

    detector = YaraDetector(scanner=scanner)
    findings = detector.analyze_file(test_file)
    assert findings
    assert findings[0].severity == "medium"


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


# -- low-quality rule confidence floor (SFE-box) ---------------------------
# Community rulesets include broad, low-severity rules that fire on benign
# files. An opt-in min_confidence floor lets callers drop matches that land
# below a quality threshold WITHOUT changing the default behavior (the floor
# defaults to 0.0, so existing scenarios and callers are unaffected).


def test_min_confidence_defaults_to_no_floor(
    scanner_multi: YaraScanner, both_file: Path
) -> None:
    # Default construction keeps every match (back-compat: scenario 11 etc.).
    detector = YaraDetector(scanner=scanner_multi)
    findings = detector.analyze_file(both_file)
    assert len(findings) >= 2


def test_min_confidence_floor_drops_low_severity_match(tmp_path: Path) -> None:
    # A broad severity=low rule (base conf 0.50) lands below a 0.60 floor and
    # is dropped, while a HIGH-severity hit on the same file survives.
    (tmp_path / "mz.yar").write_text(_MZ_HIGH_RULE)
    (tmp_path / "benign.yar").write_text(_BENIGN_LOW_RULE)
    scanner = YaraScanner.compile_from_directory(tmp_path)
    target = tmp_path / "mixed.bin"
    target.write_bytes(b"MZ\x90\x00 contains BENIGN marker")
    detector = YaraDetector(scanner=scanner, min_confidence=0.60)
    findings = detector.analyze_file(target)
    rules = {f.evidence["rule"] for f in findings}
    assert "mz_header_high" in rules
    assert "benign_low" not in rules


def test_min_confidence_floor_applies_in_directory_scan(tmp_path: Path) -> None:
    (tmp_path / "benign.yar").write_text(_BENIGN_LOW_RULE)
    scanner = YaraScanner.compile_from_directory(tmp_path)
    sample = tmp_path / "doc.txt"
    sample.write_text("this file is BENIGN")
    detector = YaraDetector(scanner=scanner, min_confidence=0.60)
    assert detector.analyze_directory(tmp_path) == []


def test_min_confidence_floor_keeps_eicar_grade_match(tmp_path: Path) -> None:
    # The EICAR rule (high + family + mitre -> 0.95) must survive any sane floor:
    # scenario 11 stays F1=1.00 even if a deployment opts into a floor.
    (tmp_path / "mz.yar").write_text(_MZ_HIGH_RULE)
    scanner = YaraScanner.compile_from_directory(tmp_path)
    target = tmp_path / "sample.bin"
    target.write_bytes(b"MZ\x90\x00")
    detector = YaraDetector(scanner=scanner, min_confidence=0.85)
    findings = detector.analyze_file(target)
    assert len(findings) == 1
    assert findings[0].evidence["rule"] == "mz_header_high"


def test_invalid_min_confidence_raises(scanner_high: YaraScanner) -> None:
    with pytest.raises(ValueError, match="min_confidence"):
        YaraDetector(scanner=scanner_high, min_confidence=-0.1)
    with pytest.raises(ValueError, match="min_confidence"):
        YaraDetector(scanner=scanner_high, min_confidence=1.5)


# -- analysis-gap diagnostic on skipped files (SFE-fuk) --------------------
# A directory scan silently drops files it cannot read (OSError on real
# evidence) or that exceed max_file_size. Those files were never scanned, so
# an empty match set must NOT be read as "directory clean". analyze_directory
# emits one ANALYSIS_GAP diagnostic when any file was skipped — mirroring the
# memory detector's list-walk gap. The gap must never be scored as a malware
# match (keeps scenario 11_yara_malware at F1=1.00).


def test_analyze_directory_no_gap_when_all_scanned(
    scanner_multi: YaraScanner, tmp_path: Path
) -> None:
    """Baseline: a fully-scanned directory emits no ANALYSIS_GAP finding.

    This protects scenario 11_yara_malware — a clean scan stays clean, so no
    spurious diagnostic dilutes the findings output.
    """
    targets = tmp_path / "targets"
    targets.mkdir()
    (targets / "a.bin").write_bytes(b"MZ\x90\x00")
    (targets / "c.txt").write_text("clean")
    detector = YaraDetector(scanner=scanner_multi)
    findings = detector.analyze_directory(targets)
    gaps = [f for f in findings if f.category == FindingCategory.ANALYSIS_GAP]
    assert gaps == []


def test_analyze_directory_emits_gap_for_oversized(tmp_path: Path) -> None:
    """An oversized (unscanned) file surfaces as an ANALYSIS_GAP finding."""
    (tmp_path / "mz.yar").write_text(_MZ_HIGH_RULE)
    # 8-byte cap: the sample below exceeds it and is skipped without scanning.
    scanner = YaraScanner.compile_from_directory(tmp_path, max_file_size=8)
    targets = tmp_path / "targets"
    targets.mkdir()
    (targets / "big.bin").write_bytes(b"MZ\x90\x00" + b"A" * 1000)
    detector = YaraDetector(scanner=scanner)
    findings = detector.analyze_directory(targets)
    gaps = [f for f in findings if f.category == FindingCategory.ANALYSIS_GAP]
    assert len(gaps) == 1
    gap = gaps[0]
    assert gap.finding_type == "diagnostic"
    assert gap.severity == "info"
    assert gap.category == FindingCategory.ANALYSIS_GAP
    assert gap.evidence["oversized_count"] == 1
    assert gap.evidence["unreadable_count"] == 0
    assert gap.evidence["skipped_count"] == 1
    assert gap.artifact_sources == ["yara"]


def test_gap_finding_is_not_scored_as_malware(tmp_path: Path) -> None:
    """The gap diagnostic must not carry the malware_classification category.

    _score counts yara true-positives by malware_classification and false-
    positives by evidence['executable']; the gap must have neither so it can
    never inflate either bucket.
    """
    (tmp_path / "mz.yar").write_text(_MZ_HIGH_RULE)
    scanner = YaraScanner.compile_from_directory(tmp_path, max_file_size=8)
    targets = tmp_path / "targets"
    targets.mkdir()
    (targets / "big.bin").write_bytes(b"MZ\x90\x00" + b"A" * 1000)
    detector = YaraDetector(scanner=scanner)
    gap = next(
        f
        for f in detector.analyze_directory(targets)
        if f.category == FindingCategory.ANALYSIS_GAP
    )
    assert gap.category != FindingCategory.MALWARE_CLASSIFICATION
    assert "executable" not in gap.evidence


def test_analyze_directory_still_reports_matches_alongside_gap(
    tmp_path: Path,
) -> None:
    """A real match and a skipped file coexist: gap does not suppress hits."""
    (tmp_path / "mz.yar").write_text(_MZ_HIGH_RULE)
    scanner = YaraScanner.compile_from_directory(tmp_path, max_file_size=8)
    targets = tmp_path / "targets"
    targets.mkdir()
    (targets / "small.bin").write_bytes(b"MZ\x90\x00")  # 4 bytes: scanned, matches
    (targets / "big.bin").write_bytes(b"MZ\x90\x00" + b"A" * 1000)  # skipped
    detector = YaraDetector(scanner=scanner)
    findings = detector.analyze_directory(targets)
    rules = {f.evidence.get("rule") for f in findings}
    gaps = [f for f in findings if f.category == FindingCategory.ANALYSIS_GAP]
    assert "mz_header_high" in rules
    assert len(gaps) == 1


def test_analyze_directory_emits_gap_for_unreadable(
    scanner_high: YaraScanner, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Unreadable files (OSError on real evidence) surface as ANALYSIS_GAP.

    Filesystem permission behavior is not portable (root bypasses chmod 000),
    so we drive the detector through a crafted DirectoryScanResult that reports
    an unreadable skip — exactly what _scan_directory_impl produces on an
    OSError.
    """
    from types import MappingProxyType

    from sift_find_evil.yara_scan.scanner import DirectoryScanResult

    bad = tmp_path / "locked.sqlite"
    result = DirectoryScanResult(
        matches=MappingProxyType({}),
        oversized=(),
        unreadable=(bad,),
    )
    monkeypatch.setattr(
        scanner_high,
        "scan_directory_details",
        lambda root, *, recursive=True: result,
    )
    detector = YaraDetector(scanner=scanner_high)
    findings = detector.analyze_directory(tmp_path)
    gaps = [f for f in findings if f.category == FindingCategory.ANALYSIS_GAP]
    assert len(gaps) == 1
    gap = gaps[0]
    assert gap.evidence["unreadable_count"] == 1
    assert gap.evidence["oversized_count"] == 0
    assert str(bad) in gap.evidence["unreadable_sample"]


def test_gap_counts_both_oversized_and_unreadable(
    scanner_high: YaraScanner, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A scan that skips BOTH kinds folds both into one gap with both reasons."""
    from types import MappingProxyType

    from sift_find_evil.yara_scan.scanner import DirectoryScanResult

    big = tmp_path / "big.bin"
    locked = tmp_path / "locked.sqlite"
    result = DirectoryScanResult(
        matches=MappingProxyType({}),
        oversized=(big,),
        unreadable=(locked,),
    )
    monkeypatch.setattr(
        scanner_high,
        "scan_directory_details",
        lambda root, *, recursive=True: result,
    )
    detector = YaraDetector(scanner=scanner_high)
    gap = next(
        f
        for f in detector.analyze_directory(tmp_path)
        if f.category == FindingCategory.ANALYSIS_GAP
    )
    assert gap.evidence["oversized_count"] == 1
    assert gap.evidence["unreadable_count"] == 1
    assert gap.evidence["skipped_count"] == 2
    # Both reasons narrated in the human-facing description.
    assert "unreadable" in gap.description
    assert "size cap" in gap.description


def test_gap_evidence_truncates_large_skip_lists(
    scanner_high: YaraScanner, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Counts are exact; path samples are capped so the finding stays shippable."""
    from types import MappingProxyType

    from sift_find_evil.yara_scan.scanner import DirectoryScanResult

    many = tuple(tmp_path / f"f{i}.bin" for i in range(120))
    result = DirectoryScanResult(
        matches=MappingProxyType({}),
        oversized=many,
        unreadable=(),
    )
    monkeypatch.setattr(
        scanner_high,
        "scan_directory_details",
        lambda root, *, recursive=True: result,
    )
    detector = YaraDetector(scanner=scanner_high)
    gap = next(
        f
        for f in detector.analyze_directory(tmp_path)
        if f.category == FindingCategory.ANALYSIS_GAP
    )
    assert gap.evidence["oversized_count"] == 120
    assert gap.evidence["skipped_count"] == 120
    assert len(gap.evidence["oversized_sample"]) == 50
    assert gap.evidence["sample_truncated"] is True
