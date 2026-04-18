"""Tests for adversarial validator."""

from datetime import datetime, timezone
from sift_find_evil.validation import AdversarialValidator


class MockFinding:
    """Mock finding for testing."""

    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)


def test_hash_format_valid():
    """Valid SHA-256 passes validation."""
    validator = AdversarialValidator()

    finding = MockFinding(
        title="Test finding",
        evidence={
            "file_sha256": "a" * 64,  # Valid 64 hex chars
        },
    )

    check = validator._check_hash_format(finding)
    assert check.passed
    assert len(check.issues) == 0


def test_hash_format_invalid_length():
    """SHA-256 with wrong length fails."""
    validator = AdversarialValidator()

    finding = MockFinding(
        title="Test finding",
        evidence={
            "file_sha256": "abc123",  # Too short
        },
    )

    check = validator._check_hash_format(finding)
    assert not check.passed
    assert "expected 64 lowercase hex characters" in check.issues[0]


def test_hash_format_invalid_chars():
    """SHA-256 with non-hex characters fails."""
    validator = AdversarialValidator()

    finding = MockFinding(
        title="Test finding",
        evidence={
            "file_sha256": "g" * 64,  # 'g' is not hex
        },
    )

    check = validator._check_hash_format(finding)
    assert not check.passed


def test_reasoning_logic_causality_violation():
    """File modified after email sent violates causality."""
    validator = AdversarialValidator()

    finding = MockFinding(
        title="Test exfil",
        category="data_exfiltration",
        description="File was saved and then emailed",
        evidence={
            "file_modified": "2009-12-11T01:30:00+00:00",  # After email!
            "email_sent": "2009-12-11T01:28:00+00:00",
        },
    )

    check = validator._check_reasoning_logic(finding)
    assert not check.passed
    assert "Causality violation" in check.issues[0]


def test_reasoning_logic_causality_valid():
    """File modified before email sent passes."""
    validator = AdversarialValidator()

    finding = MockFinding(
        title="Test exfil",
        category="data_exfiltration",
        description="File was saved and then emailed",
        evidence={
            "file_modified": "2009-12-11T01:28:00+00:00",
            "email_sent": "2009-12-11T01:29:00+00:00",  # After file
        },
    )

    check = validator._check_reasoning_logic(finding)
    assert check.passed


def test_confidence_justification_high_delta():
    """0.95 confidence with >60s delta gets warning."""
    validator = AdversarialValidator()

    finding = MockFinding(
        title="Test exfil",
        category="data_exfiltration",
        confidence=0.95,
        evidence={
            "time_delta_seconds": 180,  # 3 minutes
        },
    )

    check = validator._check_confidence_justification(finding)
    assert not check.passed
    assert "may be too high" in check.issues[0]


def test_confidence_justification_low_delta():
    """0.95 confidence with <60s delta passes."""
    validator = AdversarialValidator()

    finding = MockFinding(
        title="Test exfil",
        category="data_exfiltration",
        confidence=0.95,
        evidence={
            "time_delta_seconds": 44,  # 44 seconds
        },
    )

    check = validator._check_confidence_justification(finding)
    assert check.passed


def test_alternative_explanations_missing():
    """Long time delta without mentioning backup gets warning."""
    validator = AdversarialValidator()

    finding = MockFinding(
        title="Test exfil",
        category="data_exfiltration",
        reasoning_chain=[
            "File was saved",
            "Email was sent 3 minutes later",
        ],
        evidence={
            "time_delta_seconds": 180,
        },
    )

    check = validator._check_alternative_explanations(finding)
    assert not check.passed
    assert "automated backup" in check.issues[0]


def test_alternative_explanations_addressed():
    """Backup mentioned in reasoning passes."""
    validator = AdversarialValidator()

    finding = MockFinding(
        title="Test exfil",
        category="data_exfiltration",
        reasoning_chain=[
            "File was saved",
            "Email was sent 3 minutes later",
            "No backup software detected on system",
        ],
        evidence={
            "time_delta_seconds": 180,
        },
    )

    check = validator._check_alternative_explanations(finding)
    assert check.passed


def test_temporal_consistency_mixed_timezones():
    """Mixed timezone-aware and naive timestamps fails."""
    validator = AdversarialValidator()

    finding = MockFinding(
        title="Test finding",
        evidence={
            "file_modified": "2009-12-11T01:28:00+00:00",  # Timezone-aware
            "email_sent": "2009-12-11T01:29:00",  # Naive
        },
    )

    check = validator._check_temporal_consistency(finding)
    assert not check.passed
    assert "Mixed timezone" in check.issues[0]


def test_temporal_consistency_all_aware():
    """All timezone-aware timestamps pass."""
    validator = AdversarialValidator()

    finding = MockFinding(
        title="Test finding",
        evidence={
            "file_modified": "2009-12-11T01:28:00+00:00",
            "email_sent": "2009-12-11T01:29:00+00:00",
        },
    )

    check = validator._check_temporal_consistency(finding)
    assert check.passed


def test_evidence_completeness_hash_missing():
    """Reasoning mentions hash but evidence lacks it."""
    validator = AdversarialValidator()

    finding = MockFinding(
        title="Test finding",
        reasoning_chain=[
            "File SHA-256 matches attachment",
        ],
        evidence={
            # No hash field!
        },
    )

    check = validator._check_evidence_completeness(finding)
    assert not check.passed
    assert "hash" in check.issues[0].lower()


def test_evidence_completeness_hash_present():
    """Reasoning mentions hash and evidence has it."""
    validator = AdversarialValidator()

    finding = MockFinding(
        title="Test finding",
        reasoning_chain=[
            "File SHA-256 matches attachment",
        ],
        evidence={
            "file_sha256": "a" * 64,
        },
    )

    check = validator._check_evidence_completeness(finding)
    assert check.passed


def test_full_validation_report():
    """Full validation produces proper report."""
    validator = AdversarialValidator()

    finding = MockFinding(
        title="Valid exfil finding",
        category="data_exfiltration",
        confidence=0.95,
        description="File saved then emailed",
        reasoning_chain=[
            "File saved at 2009-12-11 01:28:03",
            "Email sent at 2009-12-11 01:28:47",
            "SHA-256 match confirms same file",
        ],
        evidence={
            "file_sha256": "34456b5f714dc9d8dd23c742d54c3f5f582ecb042bc1c4d3042b88203863779f",
            "file_modified": "2009-12-11T01:28:03+00:00",
            "email_sent": "2009-12-11T01:28:47+00:00",
            "time_delta_seconds": 44,
        },
    )

    report = validator.validate(finding)

    assert report.passed
    assert len(report.critical_issues) == 0
    assert len(report.checks) == 6


def test_validation_report_critical_issues():
    """Critical issues properly classified."""
    validator = AdversarialValidator()

    finding = MockFinding(
        title="Invalid finding",
        category="data_exfiltration",
        confidence=0.95,
        description="Bad hash and causality violation",
        evidence={
            "file_sha256": "bad_hash",  # Invalid format (critical)
            "file_modified": "2009-12-11T01:30:00+00:00",
            "email_sent": "2009-12-11T01:28:00+00:00",  # Before file (critical)
        },
    )

    report = validator.validate(finding)

    assert not report.passed
    assert len(report.critical_issues) >= 2  # Hash + causality
    assert any("Invalid SHA-256" in issue for issue in report.critical_issues)
    assert any("Causality violation" in issue for issue in report.critical_issues)


def test_validation_report_warnings_only():
    """Warnings don't fail validation but are noted."""
    validator = AdversarialValidator()

    finding = MockFinding(
        title="Finding with warnings",
        category="data_exfiltration",
        confidence=0.95,
        description="Valid but with high time delta",
        reasoning_chain=["File saved", "Email sent"],
        evidence={
            "file_sha256": "a" * 64,  # Valid
            "file_modified": "2009-12-11T01:28:00+00:00",
            "email_sent": "2009-12-11T01:31:00+00:00",  # Valid order
            "time_delta_seconds": 180,  # High delta (warning)
        },
    )

    report = validator.validate(finding)

    assert report.passed  # No critical issues
    assert len(report.critical_issues) == 0
    assert len(report.warnings) >= 1  # Confidence + alternative explanations
    assert any("may be too high" in warn for warn in report.warnings)
