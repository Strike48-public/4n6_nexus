"""Tests for Linux sudoers parser.

Verifies parsing of /etc/sudoers and /etc/sudoers.d/* including:
- #includedir / @includedir / #include directives
- Line continuation with backslashes
- Integration with LinuxPersistenceDetector
"""

from __future__ import annotations

from pathlib import Path

from sift_find_evil.detectors.linux_persistence import LinuxPersistenceDetector
from sift_find_evil.parsers.linux_sudoers import parse_sudoers


def test_parse_main_sudoers_only(tmp_path: Path) -> None:
    """Parse a standalone /etc/sudoers without any includes."""
    etc = tmp_path / "etc"
    etc.mkdir()

    (etc / "sudoers").write_text(
        "# Comment line\n"
        "Defaults env_reset\n"
        "root ALL=(ALL:ALL) ALL\n"
        "attacker ALL=(ALL) NOPASSWD:ALL\n"
    )

    result = parse_sudoers(tmp_path)

    assert len(result) == 4
    assert result[0] == {"path": "/etc/sudoers", "line": "# Comment line"}
    assert result[1] == {"path": "/etc/sudoers", "line": "Defaults env_reset"}
    assert result[2] == {"path": "/etc/sudoers", "line": "root ALL=(ALL:ALL) ALL"}
    assert result[3] == {
        "path": "/etc/sudoers",
        "line": "attacker ALL=(ALL) NOPASSWD:ALL",
    }


def test_parse_with_includedir(tmp_path: Path) -> None:
    """Parse /etc/sudoers with #includedir directive."""
    etc = tmp_path / "etc"
    etc.mkdir()
    sudoers_d = etc / "sudoers.d"
    sudoers_d.mkdir()

    (etc / "sudoers").write_text(
        "Defaults env_reset\n"
        "%wheel ALL=(ALL) NOPASSWD:ALL\n"
        "#includedir /etc/sudoers.d\n"
    )

    (sudoers_d / "backdoor").write_text("attacker ALL=(ALL) NOPASSWD:ALL\n")
    (sudoers_d / "devops").write_text("deploy ALL=(ALL) NOPASSWD: /usr/bin/systemctl\n")

    result = parse_sudoers(tmp_path)

    # Should have entries from main sudoers and both included files
    paths = {entry["path"] for entry in result}
    assert "/etc/sudoers" in paths
    assert "/etc/sudoers.d/backdoor" in paths
    assert "/etc/sudoers.d/devops" in paths

    # Check specific entries
    backdoor_lines = [
        e["line"] for e in result if e["path"] == "/etc/sudoers.d/backdoor"
    ]
    assert "attacker ALL=(ALL) NOPASSWD:ALL" in backdoor_lines


def test_parse_with_at_includedir(tmp_path: Path) -> None:
    """Parse /etc/sudoers with @includedir directive."""
    etc = tmp_path / "etc"
    etc.mkdir()
    sudoers_d = etc / "sudoers.d"
    sudoers_d.mkdir()

    (etc / "sudoers").write_text(
        "root ALL=(ALL:ALL) ALL\n" "@includedir /etc/sudoers.d\n"
    )

    (sudoers_d / "custom").write_text("testuser ALL=(ALL) NOPASSWD:ALL\n")

    result = parse_sudoers(tmp_path)

    paths = {entry["path"] for entry in result}
    assert "/etc/sudoers.d/custom" in paths


def test_parse_with_include_file(tmp_path: Path) -> None:
    """Parse /etc/sudoers with #include <file> directive."""
    etc = tmp_path / "etc"
    etc.mkdir()

    custom_path = etc / "sudoers.custom"
    custom_path.write_text("custom_user ALL=(ALL) NOPASSWD:ALL\n")

    (etc / "sudoers").write_text(
        "root ALL=(ALL:ALL) ALL\n" "#include /etc/sudoers.custom\n"
    )

    result = parse_sudoers(tmp_path)

    paths = {entry["path"] for entry in result}
    assert "/etc/sudoers.custom" in paths

    custom_lines = [e["line"] for e in result if e["path"] == "/etc/sudoers.custom"]
    assert "custom_user ALL=(ALL) NOPASSWD:ALL" in custom_lines


def test_line_continuation(tmp_path: Path) -> None:
    """Parse sudoers entries with backslash line continuation."""
    etc = tmp_path / "etc"
    etc.mkdir()

    (etc / "sudoers").write_text(
        "user1 ALL=(ALL) \\\n"
        "    NOPASSWD:ALL\n"
        "user2 ALL=(ALL) NOPASSWD: /usr/bin/systemctl, \\\n"
        "                          /usr/bin/journalctl\n"
    )

    result = parse_sudoers(tmp_path)

    assert len(result) == 2
    # Line continuation should join the lines
    assert "user1 ALL=(ALL)     NOPASSWD:ALL" in result[0]["line"]
    assert "user2 ALL=(ALL) NOPASSWD: /usr/bin/systemctl," in result[1]["line"]
    assert "/usr/bin/journalctl" in result[1]["line"]


def test_skip_empty_lines(tmp_path: Path) -> None:
    """Empty lines should be skipped."""
    etc = tmp_path / "etc"
    etc.mkdir()

    (etc / "sudoers").write_text(
        "root ALL=(ALL:ALL) ALL\n" "\n" "   \n" "user ALL=(ALL) NOPASSWD:ALL\n"
    )

    result = parse_sudoers(tmp_path)

    # Should only have the two non-empty lines
    assert len(result) == 2
    lines = [e["line"] for e in result]
    assert "root ALL=(ALL:ALL) ALL" in lines
    assert "user ALL=(ALL) NOPASSWD:ALL" in lines


def test_integration_with_detector_backdoor(tmp_path: Path) -> None:
    """Integration test: backdoor should generate a finding."""
    etc = tmp_path / "etc"
    etc.mkdir()
    sudoers_d = etc / "sudoers.d"
    sudoers_d.mkdir()

    (etc / "sudoers").write_text(
        "Defaults env_reset\n"
        "# Comment\n"
        "%wheel ALL=(ALL) NOPASSWD:ALL\n"
        "#includedir /etc/sudoers.d\n"
    )

    (sudoers_d / "backdoor").write_text("attacker ALL=(ALL) NOPASSWD:ALL\n")

    parsed = parse_sudoers(tmp_path)
    detector = LinuxPersistenceDetector()
    findings = detector.analyze({"sudoers": parsed})

    # Should find exactly one issue: the attacker line
    assert len(findings) == 1
    finding = findings[0]
    assert "attacker" in finding.title.lower() or "attacker" in finding.description
    assert finding.severity == "high"
    assert finding.category.value == "persistence"
    assert "backdoor" in finding.evidence["path"]


def test_integration_with_detector_benign_system_principals(tmp_path: Path) -> None:
    """Integration test: system principals should NOT generate findings."""
    etc = tmp_path / "etc"
    etc.mkdir()

    (etc / "sudoers").write_text(
        "root ALL=(ALL:ALL) ALL\n"
        "%wheel ALL=(ALL) NOPASSWD:ALL\n"
        "%sudo ALL=(ALL) NOPASSWD:ALL\n"
        "%admin ALL=(ALL) NOPASSWD:ALL\n"
    )

    parsed = parse_sudoers(tmp_path)
    detector = LinuxPersistenceDetector()
    findings = detector.analyze({"sudoers": parsed})

    # No findings - all are system principals
    assert len(findings) == 0


def test_mutation_check_attacker_becomes_root(tmp_path: Path) -> None:
    """Mutation test: changing attacker -> root should eliminate the finding."""
    etc = tmp_path / "etc"
    etc.mkdir()

    # Original: attacker (should find)
    (etc / "sudoers").write_text("attacker ALL=(ALL) NOPASSWD:ALL\n")
    parsed = parse_sudoers(tmp_path)
    detector = LinuxPersistenceDetector()
    findings = detector.analyze({"sudoers": parsed})
    assert len(findings) == 1

    # Mutate: change to root (should NOT find)
    (etc / "sudoers").write_text("root ALL=(ALL) NOPASSWD:ALL\n")
    parsed_mutated = parse_sudoers(tmp_path)
    findings_mutated = detector.analyze({"sudoers": parsed_mutated})
    assert len(findings_mutated) == 0


def test_mutation_check_attacker_becomes_wheel(tmp_path: Path) -> None:
    """Mutation test: changing attacker -> %wheel should eliminate the finding."""
    etc = tmp_path / "etc"
    etc.mkdir()

    # Original: attacker (should find)
    (etc / "sudoers").write_text("attacker ALL=(ALL) NOPASSWD:ALL\n")
    parsed = parse_sudoers(tmp_path)
    detector = LinuxPersistenceDetector()
    findings = detector.analyze({"sudoers": parsed})
    assert len(findings) == 1

    # Mutate: change to %wheel (should NOT find)
    (etc / "sudoers").write_text("%wheel ALL=(ALL) NOPASSWD:ALL\n")
    parsed_mutated = parse_sudoers(tmp_path)
    findings_mutated = detector.analyze({"sudoers": parsed_mutated})
    assert len(findings_mutated) == 0


def test_missing_sudoers_returns_empty(tmp_path: Path) -> None:
    """Parser should return empty list if /etc/sudoers doesn't exist."""
    result = parse_sudoers(tmp_path)
    assert result == []


def test_missing_sudoers_d_directory(tmp_path: Path) -> None:
    """Parser should handle missing sudoers.d directory gracefully."""
    etc = tmp_path / "etc"
    etc.mkdir()

    (etc / "sudoers").write_text(
        "root ALL=(ALL:ALL) ALL\n" "#includedir /etc/sudoers.d\n"
    )

    # sudoers.d directory doesn't exist
    result = parse_sudoers(tmp_path)

    # Should still parse the main file
    assert len(result) == 2
    assert result[0]["path"] == "/etc/sudoers"


def test_include_cycle_does_not_recurse_forever(tmp_path: Path) -> None:
    """A self-referential #include must terminate (cycle guard)."""
    etc = tmp_path / "etc"
    etc.mkdir()
    # sudoers includes itself -> would infinite-loop without a visited guard.
    (etc / "sudoers").write_text(
        "#include /etc/sudoers\nattacker ALL=(ALL) NOPASSWD:ALL\n"
    )

    entries = parse_sudoers(tmp_path)

    # Terminates, and the backdoor line is captured exactly once.
    backdoors = [e for e in entries if "attacker" in e["line"]]
    assert len(backdoors) == 1
    findings = LinuxPersistenceDetector().analyze({"sudoers": entries})
    assert len(findings) == 1


def test_include_path_traversal_is_contained(tmp_path: Path) -> None:
    """An #include escaping the mounted root via .. must not read host files."""
    root = tmp_path / "mnt"
    (root / "etc").mkdir(parents=True)
    # A secret file OUTSIDE the mounted root the parser must never read. Includes
    # are resolved relative to root, so `../secret_sudoers` resolves to
    # tmp_path/secret_sudoers (one level above root) -- a REAL file on disk.
    # Only the containment check keeps its contents out of the results.
    outside = tmp_path / "secret_sudoers"
    outside.write_text("hostuser ALL=(ALL) NOPASSWD:ALL\n")
    (root / "etc" / "sudoers").write_text("#include ../secret_sudoers\n")

    entries = parse_sudoers(root)

    # The out-of-root file's content must not appear in the parsed entries.
    assert all("hostuser" not in e["line"] for e in entries)


def test_binary_sudoers_does_not_crash(tmp_path: Path) -> None:
    """A binary/non-UTF8 sudoers file degrades to a skip, not a crash."""
    etc = tmp_path / "etc"
    etc.mkdir()
    (etc / "sudoers").write_bytes(b"\xff\xfe\x00\x01 binary garbage")

    # Must not raise; content is unparseable so no meaningful entries.
    result = parse_sudoers(tmp_path)
    assert isinstance(result, list)
