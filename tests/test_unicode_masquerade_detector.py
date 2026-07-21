"""Tests for the Unicode masquerade / RLO / zero-width filename+string detector."""

from sift_find_evil.detectors.unicode_masquerade_detector import (
    UnicodeMasqueradeDetector,
)
from sift_find_evil.findings import FindingCategory


def test_rlo_filename_flagged_with_mitre_technique() -> None:
    # Arrange: classic RLO trick "invoice<RLO>gpj.exe" displays as "invoiceexe.jpg"
    detector = UnicodeMasqueradeDetector()
    strings = [("mft_filename", "invoice‮gpj.exe")]

    # Act
    findings = detector.analyze(strings)

    # Assert
    assert len(findings) == 1
    finding = findings[0]
    assert finding.finding_type == "indicator"
    assert finding.severity == "high"
    assert finding.category == FindingCategory.ANTI_FORENSICS
    assert finding.confidence == 0.9
    assert "T1036.002" in finding.evidence["mitre_attack"]
    assert finding.evidence["source"] == "mft_filename"
    # RLO present -> a display-vs-real extension hint is reported
    assert "display_vs_real" in finding.evidence


def test_zero_width_in_registry_value_flagged() -> None:
    # Arrange: zero-width joiner hidden in a registry value
    detector = UnicodeMasqueradeDetector()
    strings = [("registry_value", "svc‍host.exe")]

    # Act
    findings = detector.analyze(strings)

    # Assert
    assert len(findings) == 1
    assert findings[0].evidence["source"] == "registry_value"
    assert 0x200D in findings[0].evidence["codepoints"]


def test_codepoints_reported_and_value_repr_escaped() -> None:
    # Arrange
    detector = UnicodeMasqueradeDetector()
    strings = [("path", "a​b")]

    # Act
    findings = detector.analyze(strings)

    # Assert
    assert len(findings) == 1
    evidence = findings[0].evidence
    assert 0x200B in evidence["codepoints"]
    # value_repr is escaped, so the raw zero-width char must not appear literally
    assert "​" not in evidence["value_repr"]
    assert "200b" in evidence["value_repr"].lower()


def test_plain_ascii_filename_yields_nothing() -> None:
    # Arrange: inverse/negative control
    detector = UnicodeMasqueradeDetector()
    strings = [
        ("mft_filename", "invoice.exe"),
        ("registry_value", "C:/Windows/System32/svchost.exe"),
        ("path", "normal_report_2026.pdf"),
    ]

    # Act
    findings = detector.analyze(strings)

    # Assert
    assert findings == []


def test_does_not_mutate_input() -> None:
    # Arrange
    detector = UnicodeMasqueradeDetector()
    strings = [("mft_filename", "invoice‮gpj.exe")]
    original = list(strings)

    # Act
    detector.analyze(strings)

    # Assert
    assert strings == original
