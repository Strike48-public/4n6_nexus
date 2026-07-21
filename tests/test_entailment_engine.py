"""Tests for the deterministic evidence re-derivation / entailment engine.

These tests validate that asserted finding values are structurally checked
against raw parser output, so that hallucinated values (substrings, absent
identity anchors) become unconfirmable. Every positive case is paired with an
inverse/negative control.
"""

from __future__ import annotations

from sift_find_evil.findings import Finding, FindingCategory
from sift_find_evil.findings.entailment import (
    EntailmentReport,
    FieldCheck,
    check_entailment,
    entail_finding,
)


def test_genuine_values_are_all_supported() -> None:
    """Values that appear verbatim on token boundaries are supported."""
    # Arrange
    observed = "process explorer.exe pid 459 hash abcd1234ef567890 addr 10.0.0.5"
    asserted = [
        {"path": "proc.pid", "expected": "459", "kind": "pid"},
        {"path": "proc.name", "expected": "explorer.exe", "kind": "filename"},
        {"path": "net.ip", "expected": "10.0.0.5", "kind": "ipv4"},
    ]

    # Act
    report = check_entailment(asserted, observed)

    # Assert
    assert report.all_supported is True
    assert all(c.matched for c in report.checks)
    assert not any(c.retract for c in report.checks)


def test_fabricated_pid_substring_fails_on_boundary() -> None:
    """A pid that only occurs inside a larger number does not match."""
    # Arrange
    observed = "worker started with pid 14592 ready"
    asserted = [{"path": "proc.pid", "expected": "459", "kind": "pid"}]

    # Act
    report = check_entailment(asserted, observed)

    # Assert - inverse control: 459 must NOT match inside 14592
    assert report.all_supported is False
    assert report.checks[0].matched is False


def test_generic_word_not_matched_inside_larger_word() -> None:
    """A generic token does not match as a substring of another word."""
    # Arrange
    observed = "senator mccain gave a speech"
    asserted = [{"path": "person", "expected": "cain", "kind": "generic"}]

    # Act
    report = check_entailment(asserted, observed)

    # Assert - 'cain' must not match inside 'mccain'
    assert report.checks[0].matched is False


def test_absent_sha256_forces_retract() -> None:
    """An identity-anchor hash that is absent forces retraction."""
    # Arrange
    observed = "no hashes were recorded in this artifact output"
    fake_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    asserted = [{"path": "file.sha256", "expected": fake_hash, "kind": "hash"}]

    # Act
    report = check_entailment(asserted, observed)

    # Assert
    assert report.all_supported is False
    assert report.checks[0].retract is True
    assert report.checks[0].observed is False


def test_present_sha256_does_not_retract() -> None:
    """Inverse control: a hash that IS present must not retract."""
    # Arrange
    real_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    observed = f"file digest sha256={real_hash} verified"
    asserted = [{"path": "file.sha256", "expected": real_hash, "kind": "hash"}]

    # Act
    report = check_entailment(asserted, observed)

    # Assert
    assert report.all_supported is True
    assert report.checks[0].retract is False
    assert report.checks[0].matched is True


def test_fabricated_ipv4_forces_retract() -> None:
    """An IPv4 identity anchor that is absent forces retraction."""
    # Arrange
    observed = "connection to 10.0.0.5 established over port 443"
    asserted = [{"path": "net.ip", "expected": "192.168.1.77", "kind": "ipv4"}]

    # Act
    report = check_entailment(asserted, observed)

    # Assert
    assert report.all_supported is False
    assert report.checks[0].retract is True


def test_ipv4_boundary_not_substring() -> None:
    """An IPv4 must match on octet boundaries, not as a digit substring."""
    # Arrange - expected ip appears as substring of a larger dotted string
    observed = "route 110.0.0.55 configured"
    asserted = [{"path": "net.ip", "expected": "10.0.0.5", "kind": "ipv4"}]

    # Act
    report = check_entailment(asserted, observed)

    # Assert - identity anchor absent -> retract
    assert report.checks[0].matched is False
    assert report.checks[0].retract is True


def test_generic_miss_downgrades_but_no_retract() -> None:
    """A corroborating generic miss lowers support but does not force retract."""
    # Arrange
    observed = "explorer.exe launched at boot"
    asserted = [
        {"path": "proc.name", "expected": "explorer.exe", "kind": "filename"},
        {"path": "note", "expected": "suspicious", "kind": "generic"},
    ]

    # Act
    report = check_entailment(asserted, observed)

    # Assert
    assert report.all_supported is False  # not fully supported
    assert all(not c.retract for c in report.checks)  # but nothing retracted


def test_generic_minimum_length_enforced() -> None:
    """Generic matches under 4 chars are refused to avoid noise matches."""
    # Arrange
    observed = "the cat sat on the mat"
    asserted = [{"path": "x", "expected": "cat", "kind": "generic"}]

    # Act
    report = check_entailment(asserted, observed)

    # Assert - 3-char generic must not match
    assert report.checks[0].matched is False


def test_empty_observed_text_is_unsupported() -> None:
    """Empty observed text can support nothing."""
    # Arrange
    asserted = [{"path": "proc.pid", "expected": "459", "kind": "pid"}]

    # Act
    report = check_entailment(asserted, "")

    # Assert
    assert report.all_supported is False
    assert report.checks[0].matched is False


def test_empty_asserted_values_is_vacuously_supported() -> None:
    """No assertions means nothing to contradict."""
    # Arrange / Act
    report = check_entailment([], "anything at all")

    # Assert
    assert report.all_supported is True
    assert report.checks == []


def test_entail_finding_reads_evidence_asserted_values() -> None:
    """entail_finding pulls asserted values from finding.evidence."""
    # Arrange
    finding = Finding(
        title="Malicious process",
        description="fake",
        finding_type="indicator",
        severity="high",
        category=FindingCategory.EXECUTION,
        evidence={
            "asserted_values": [
                {"path": "proc.pid", "expected": "459", "kind": "pid"},
            ]
        },
    )
    observed = "explorer.exe pid 459 running"

    # Act
    report = entail_finding(finding, observed)

    # Assert
    assert isinstance(report, EntailmentReport)
    assert report.all_supported is True


def test_entail_finding_flags_hallucinated_hash() -> None:
    """Inverse control: entail_finding retracts on absent hash anchor."""
    # Arrange
    fake = "deadbeef" * 8
    finding = Finding(
        title="Suspicious file",
        description="fake",
        finding_type="indicator",
        severity="high",
        category=FindingCategory.EXECUTION,
        evidence={
            "asserted_values": [
                {"path": "file.sha256", "expected": fake, "kind": "hash"},
            ]
        },
    )
    observed = "no hash present in this output"

    # Act
    report = entail_finding(finding, observed)

    # Assert
    assert report.all_supported is False
    assert any(c.retract for c in report.checks)


def test_fieldcheck_fields_are_populated() -> None:
    """FieldCheck carries path, expected, kind, observed, matched, retract."""
    # Arrange
    observed = "pid 459 here"
    asserted = [{"path": "proc.pid", "expected": "459", "kind": "pid"}]

    # Act
    check = check_entailment(asserted, observed).checks[0]

    # Assert
    assert isinstance(check, FieldCheck)
    assert check.path == "proc.pid"
    assert check.expected == "459"
    assert check.kind == "pid"
    assert check.observed is True
    assert check.matched is True
    assert check.retract is False
