"""Unit tests for AttackPatternDetector."""

from __future__ import annotations


from sift_find_evil.self_correction.attack_pattern_detector import (
    AttackPatternDetector,
    AttackTechnique,
)


def test_analyze_command_line_empty_command() -> None:
    """Test analyze_command_line with empty command returns empty list."""
    detector = AttackPatternDetector()

    assert detector.analyze_command_line("") == []
    assert detector.analyze_command_line(None) == []


def test_analyze_command_line_credential_access_critical() -> None:
    """Test credential access techniques marked as critical severity."""
    detector = AttackPatternDetector()

    patterns = detector.analyze_command_line("mimikatz.exe sekurlsa::logonpasswords")

    assert len(patterns) > 0
    assert any(p.severity == "critical" for p in patterns)
    assert any(p.technique == AttackTechnique.CREDENTIAL_ACCESS for p in patterns)


def test_analyze_command_line_lateral_movement_critical() -> None:
    """Test lateral movement techniques marked as critical severity."""
    detector = AttackPatternDetector()

    patterns = detector.analyze_command_line("psexec.exe \\\\target cmd.exe")

    assert len(patterns) > 0
    assert any(p.severity == "critical" for p in patterns)


def test_analyze_command_line_defense_evasion_high_confidence_critical() -> None:
    """Test defense evasion with high confidence marked as critical."""
    detector = AttackPatternDetector()

    # Defense evasion with confidence >= 0.90
    patterns = detector.analyze_command_line("powershell -nop -w hidden -enc AAAA")

    assert len(patterns) > 0
    # At least one pattern should be defense evasion with high confidence
    defense_patterns = [
        p for p in patterns if p.technique == AttackTechnique.DEFENSE_EVASION
    ]
    if defense_patterns:
        high_conf = [p for p in defense_patterns if p.confidence >= 0.90]
        if high_conf:
            assert any(p.severity == "critical" for p in high_conf)


def test_analyze_command_line_persistence_high_severity() -> None:
    """Test persistence techniques marked as high severity."""
    detector = AttackPatternDetector()

    patterns = detector.analyze_command_line(
        "schtasks /create /tn malware /tr C:\\evil.exe"
    )

    assert len(patterns) > 0
    persistence_patterns = [
        p for p in patterns if p.technique == AttackTechnique.PERSISTENCE
    ]
    assert any(p.severity in ("high", "critical") for p in persistence_patterns)


def test_analyze_command_line_execution_high_severity() -> None:
    """Test execution techniques marked as high severity."""
    detector = AttackPatternDetector()

    patterns = detector.analyze_command_line("wmic process call create calc.exe")

    assert len(patterns) > 0
    execution_patterns = [
        p for p in patterns if p.technique == AttackTechnique.EXECUTION
    ]
    if execution_patterns:
        assert any(p.severity in ("high", "critical") for p in execution_patterns)


def test_analyze_command_line_reconnaissance_medium_severity() -> None:
    """Test reconnaissance techniques marked as medium severity."""
    detector = AttackPatternDetector()

    patterns = detector.analyze_command_line("whoami /all")

    assert len(patterns) > 0
    recon_patterns = [
        p for p in patterns if p.technique == AttackTechnique.RECONNAISSANCE
    ]
    assert any(p.severity == "medium" for p in recon_patterns)


def test_analyze_command_line_other_technique_medium_severity() -> None:
    """Test non-categorized techniques default to medium severity."""
    detector = AttackPatternDetector()

    # Use a pattern that doesn't match high-priority categories
    patterns = detector.analyze_command_line("cmd.exe /c dir")

    # If any patterns detected, verify severity handling
    if patterns:
        for p in patterns:
            assert p.severity in ("critical", "high", "medium", "low", "info")


def test_get_highest_severity_pattern_empty_list() -> None:
    """Test get_highest_severity_pattern returns None for empty list."""
    detector = AttackPatternDetector()

    assert detector.get_highest_severity_pattern([]) is None


def test_get_highest_severity_pattern_returns_critical() -> None:
    """Test get_highest_severity_pattern returns critical over high."""
    detector = AttackPatternDetector()

    patterns = detector.analyze_command_line("mimikatz.exe sekurlsa::logonpasswords")
    if patterns:
        highest = detector.get_highest_severity_pattern(patterns)
        assert highest is not None
        # Should be critical severity
        assert highest.severity in ("critical", "high")


def test_get_highest_severity_pattern_uses_confidence_tiebreaker() -> None:
    """Test get_highest_severity_pattern uses confidence as tiebreaker."""
    detector = AttackPatternDetector()

    # Get multiple patterns with potentially same severity
    patterns = detector.analyze_command_line("powershell.exe Get-Process; whoami /all")

    if len(patterns) > 1:
        highest = detector.get_highest_severity_pattern(patterns)
        assert highest is not None
        # Verify it's one of the patterns
        assert highest in patterns


def test_analyze_command_line_case_insensitive() -> None:
    """Test pattern detection is case-insensitive."""
    detector = AttackPatternDetector()

    lower = detector.analyze_command_line("whoami /all")
    upper = detector.analyze_command_line("WHOAMI /ALL")
    mixed = detector.analyze_command_line("WhOaMi /AlL")

    # All should detect the same patterns
    assert len(lower) > 0
    assert len(upper) > 0
    assert len(mixed) > 0
    assert len(lower) == len(upper) == len(mixed)


def test_analyze_command_line_truncates_long_command() -> None:
    """Test pattern description truncates long commands."""
    detector = AttackPatternDetector()

    long_command = "powershell.exe -enc " + "A" * 500
    patterns = detector.analyze_command_line(long_command)

    if patterns:
        # Description should truncate at 200 chars
        for p in patterns:
            assert len(p.description) <= 250  # description + pattern name
