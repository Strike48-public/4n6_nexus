"""Tests for the scene-staging / over-interpretation detector.

Idea #28: 'too obvious = planted'. When a forensic scene is dominated by
bait-like artifact names, the verifier should lower its confidence and
invert the analysis (look for what is NOT there).
"""

from sift_find_evil.detectors.eco_check import SceneStagingDetector
from sift_find_evil.findings import Finding, FindingCategory


def test_mostly_bait_scene_flags_staging() -> None:
    # Arrange
    evidence_terms = [
        "hacktool",
        "definitely_evil.exe",
        "totally_not_malware",
        "readme.txt",
    ]
    detector = SceneStagingDetector()

    # Act
    findings = detector.analyze(evidence_terms)

    # Assert
    assert len(findings) == 1
    finding = findings[0]
    assert isinstance(finding, Finding)
    assert finding.title == "POSSIBLE_SCENE_STAGING"
    assert finding.finding_type == "behavior"
    assert finding.severity == "medium"
    assert finding.category == FindingCategory.ANTI_FORENSICS
    assert finding.evidence["bait_hits"] == 3
    assert finding.evidence["total"] == 4


def test_reasoning_chain_includes_invert_analysis() -> None:
    # Arrange
    evidence_terms = ["mimikatz.txt", "password.txt", "notes.docx"]
    detector = SceneStagingDetector()

    # Act
    findings = detector.analyze(evidence_terms)

    # Assert
    assert len(findings) == 1
    chain_text = " ".join(findings[0].reasoning_chain).lower()
    assert "invert" in chain_text
    assert "not there" in chain_text


def test_realistic_mixed_scene_does_not_flag() -> None:
    # Arrange: one bait term amongst many normal artifacts
    evidence_terms = [
        "svchost.exe",
        "ntuser.dat",
        "Amcache.hve",
        "SYSTEM",
        "SOFTWARE",
        "prefetch\\CHROME.EXE-ABCD1234.pf",
        "password.txt",
        "setupapi.dev.log",
    ]
    detector = SceneStagingDetector()

    # Act
    findings = detector.analyze(evidence_terms)

    # Assert
    assert findings == []


def test_word_boundary_avoids_substring_false_positive() -> None:
    # Arrange: 'password.txt' is bait, but 'my_password.txt_backup' style
    # normal names should not spuriously count; a term that merely contains
    # 'hacktool' as a substring within a larger token is not a bait hit.
    evidence_terms = ["counterhacktoolkit_report", "invoice.pdf", "budget.xlsx"]
    detector = SceneStagingDetector()

    # Act
    findings = detector.analyze(evidence_terms)

    # Assert
    assert findings == []


def test_empty_input_yields_nothing() -> None:
    # Arrange
    detector = SceneStagingDetector()

    # Act
    findings = detector.analyze([])

    # Assert
    assert findings == []


def test_does_not_mutate_input() -> None:
    # Arrange
    evidence_terms = ["hacktool", "totally_not_malware", "notes.txt"]
    original = list(evidence_terms)
    detector = SceneStagingDetector()

    # Act
    detector.analyze(evidence_terms)

    # Assert
    assert evidence_terms == original
