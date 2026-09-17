"""Linux shell artifact parser (ld.so.preload and shell-init files).

Parses two persistence surfaces from a mounted Linux image root:

1. **ld.so.preload**: The dynamic linker's force-load list. Reads
   ``/etc/ld.so.preload`` and returns its raw content, or an empty string when
   the file is missing or empty. Downstream detector flags any shared object
   outside standard library paths as hijacking (T1574.006).

2. **Shell init files**: Config files that execute on interactive shell start
   (``/etc/profile``, ``/etc/bash.bashrc``, ``/etc/profile.d/*.sh``, per-user
   ``~/.bashrc``, ``~/.bash_profile``, ``~/.profile``, ``~/.zshrc``). Returns a
   list of dicts with ``"path"`` (in-image absolute) and ``"line"`` (text) for
   every non-blank, non-comment line. Downstream detector flags suspicious
   commands (reverse shells, ``curl|sh``) as persistence (T1546.004).

Input is a mounted image root; no real evidence is mutated.
"""

from __future__ import annotations

from pathlib import Path

from ._linux_fs import enumerate_user_homes, read_text_contained


def parse_ld_preload(root: Path) -> str:
    """Parse /etc/ld.so.preload from a mounted image root.

    Args:
        root: Mounted image root directory containing the filesystem tree.

    Returns:
        Raw text content of ``/etc/ld.so.preload``, or an empty string when the
        file is missing or empty. The input directory is never mutated.
    """
    preload_file = root / "etc" / "ld.so.preload"
    return read_text_contained(preload_file, root) or ""


def parse_shell_init(root: Path) -> list[dict]:
    """Parse shell init files from a mounted image root.

    Collects non-blank, non-comment lines from shell init files that execute on
    interactive shell start. Covers system-wide files (``/etc/profile``,
    ``/etc/bash.bashrc``, ``/etc/profile.d/*.sh``) and per-user files
    (``~/.bashrc``, ``~/.bash_profile``, ``~/.profile``, ``~/.zshrc``) under
    ``/root`` and ``/home/<user>``.

    Args:
        root: Mounted image root directory containing the filesystem tree.

    Returns:
        A list of dicts, one per non-blank, non-comment line. Each dict has
        ``"path"`` (in-image absolute path, root prefix stripped) and ``"line"``
        (the line text). The input directory is never mutated.
    """
    entries: list[dict] = []

    # System-wide files
    entries.extend(_parse_file(root, root / "etc" / "profile"))
    entries.extend(_parse_file(root, root / "etc" / "bash.bashrc"))

    # /etc/profile.d/*.sh
    profile_d = root / "etc" / "profile.d"
    if profile_d.exists() and profile_d.is_dir():
        for sh_file in profile_d.glob("*.sh"):
            entries.extend(_parse_file(root, sh_file))

    # Per-user files under /root and /home/<user>
    for user_home in enumerate_user_homes(root):
        for filename in (".bashrc", ".bash_profile", ".profile", ".zshrc"):
            entries.extend(_parse_file(root, user_home / filename))

    return entries


def _parse_file(root: Path, file_path: Path) -> list[dict]:
    """Parse a single shell init file into line entries.

    Args:
        root: Mounted image root directory (for stripping prefix).
        file_path: Absolute path to the file to parse.

    Returns:
        A list of dicts with ``"path"`` (in-image absolute) and ``"line"`` for
        every non-blank, non-comment line. Returns an empty list if the file
        does not exist or cannot be read.
    """
    content = read_text_contained(file_path, root)
    if content is None:
        return []

    # Strip root prefix to get in-image absolute path
    relative_path = file_path.relative_to(root)
    in_image_path = "/" + str(relative_path).replace("\\", "/")

    entries: list[dict] = []
    for line in content.splitlines():
        stripped = line.strip()
        # Skip blank lines and comments
        if not stripped or stripped.startswith("#"):
            continue
        entries.append({"path": in_image_path, "line": line})

    return entries
