"""Linux shell-history parser (SFE-jdii).

Parses per-user shell command history off a mounted image root:

- ``~/.bash_history`` (bash)
- ``~/.zsh_history`` (zsh; supports the ``EXTENDED_HISTORY`` timestamp prefix)
- ``~/.sh_history`` (ksh / POSIX sh)

under ``/root`` and each ``/home/<user>``. Each non-blank line becomes one
normalized command entry so the downstream ``LinuxExecutionDetector`` can flag
recorded malicious commands (T1059.004) without re-parsing text.

Input is a mounted image root -- attacker-controlled content -- so reads go
through :func:`read_text_contained` for symlink-escape and size protection.
The mounted root is never mutated.
"""

from __future__ import annotations

import re
from pathlib import Path

from ._linux_fs import MAX_ARTIFACT_BYTES, enumerate_user_homes, read_text_contained

# Shell-history dotfiles collected per user home.
_HISTORY_FILES: tuple[str, ...] = (".bash_history", ".zsh_history", ".sh_history")

# zsh EXTENDED_HISTORY records each command as ": <begin>:<elapsed>;<command>".
# Strip the metadata prefix so the detector sees the bare command.
_ZSH_EXTENDED = re.compile(r"^:\s+\d+:\d+;(?P<cmd>.*)$")


def parse_shell_history(root: Path) -> list[dict]:
    """Parse shell command history from a mounted image root.

    Walks ``/root`` and every ``/home/<user>`` for the known history dotfiles
    and returns one entry per non-blank recorded command.

    Args:
        root: Mounted image root directory containing the filesystem tree.

    Returns:
        A list of dicts, one per non-blank history line. Each dict has
        ``"path"`` (in-image absolute path, root prefix stripped) and
        ``"command"`` (the recorded command, zsh timestamp prefix removed).
        Missing history files yield an empty list rather than an error. The
        input directory is never mutated.
    """
    entries: list[dict] = []
    for user_home in enumerate_user_homes(root):
        for filename in _HISTORY_FILES:
            entries.extend(_parse_history_file(root, user_home / filename))
    return entries


def _parse_history_file(root: Path, file_path: Path) -> list[dict]:
    """Parse a single shell-history file into command entries."""
    content = read_text_contained(file_path, root, max_bytes=MAX_ARTIFACT_BYTES)
    if content is None:
        return []

    relative_path = file_path.relative_to(root)
    in_image_path = "/" + str(relative_path).replace("\\", "/")

    entries: list[dict] = []
    for line in content.splitlines():
        match = _ZSH_EXTENDED.match(line)
        command = match.group("cmd") if match else line
        if not command.strip():
            continue
        entries.append({"path": in_image_path, "command": command})
    return entries
