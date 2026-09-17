"""Shared filesystem safety helpers for the Linux artifact parsers.

The Linux parsers read raw files off a *mounted image root* -- i.e.
attacker-controlled content on real dead-disk evidence. Two footguns follow
directly from that and are centralised here so every parser is protected
identically:

- **Symlink / path-traversal escape.** A symlink inside the image (or a
  ``#include ../..`` directive) can point *outside* the mounted root; naively
  ``read_text()``-ing it reads the ANALYST's host filesystem, violating the
  "never read outside the evidence" rule. :func:`read_text_contained` resolves
  the real path and refuses anything that escapes ``root``.
- **Resource exhaustion / decode crash.** A planted multi-gigabyte or binary
  artifact would exhaust memory or raise ``UnicodeDecodeError`` and abort the
  whole analysis run. The helper caps the read size and decodes with
  ``errors="replace"`` so one hostile file degrades to a skip, never a crash.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

# Config artifacts (unit files, crontabs, sudoers, shell init) are kilobytes;
# 10 MiB is a generous ceiling that still stops a planted giant file.
MAX_ARTIFACT_BYTES = 10 * 1024 * 1024


def _safe_resolve(path: Path) -> Optional[Path]:
    """Resolve ``path`` to its canonical form, or None if it cannot resolve."""
    try:
        return path.resolve()
    except (OSError, RuntimeError):  # RuntimeError: symlink loop
        return None


def is_within_root(path: Path, root: Path) -> bool:
    """Return True when ``path`` resolves to a location inside ``root``.

    Both operands are resolved (symlinks followed) before comparison, so a
    symlink whose target escapes the mounted root is rejected.
    """
    resolved = _safe_resolve(path)
    root_resolved = _safe_resolve(root)
    if resolved is None or root_resolved is None:
        return False
    return resolved == root_resolved or root_resolved in resolved.parents


def enumerate_user_homes(root: Path) -> list[Path]:
    """Enumerate user home directories (``/root`` and ``/home/<user>``).

    Shared by the shell-init and shell-history parsers, which both collect
    per-user dotfiles off a mounted image root.

    Args:
        root: Mounted image root directory.

    Returns:
        Paths to the home directories that exist in the image: ``/root`` (if a
        directory) followed by each ``/home/<user>`` subdirectory.
    """
    homes: list[Path] = []

    root_home = root / "root"
    if root_home.is_dir():
        homes.append(root_home)

    home_dir = root / "home"
    if home_dir.is_dir():
        for user_dir in home_dir.iterdir():
            if user_dir.is_dir():
                homes.append(user_dir)

    return homes


def read_text_contained(
    path: Path, root: Path, *, max_bytes: int = MAX_ARTIFACT_BYTES
) -> Optional[str]:
    """Read a text file only if it is a real, in-root, reasonably-sized file.

    Args:
        path: File to read (may be a symlink).
        root: Mounted image root the file must stay within.
        max_bytes: Upper bound on file size; larger files are skipped.

    Returns:
        The file's text (decoded with ``errors="replace"``), or None when the
        path is missing, is not a regular file, escapes ``root`` via symlink or
        ``..``, exceeds ``max_bytes``, or cannot be read.
    """
    if not path.is_file() or not is_within_root(path, root):
        return None
    try:
        if path.stat().st_size > max_bytes:
            return None
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def read_bytes_contained(
    path: Path, root: Path, *, max_bytes: int = MAX_ARTIFACT_BYTES
) -> Optional[bytes]:
    """Read a binary file under the same containment guards as text reads.

    Binary artifacts (wtmp/utmp login records, and other fixed-record formats)
    cannot go through :func:`read_text_contained` -- decoding would corrupt the
    struct bytes. This sibling applies the identical symlink-escape and
    size-cap protections but returns the raw bytes undecoded.

    Args:
        path: File to read (may be a symlink).
        root: Mounted image root the file must stay within.
        max_bytes: Upper bound on file size; larger files are skipped.

    Returns:
        The file's raw bytes, or None when the path is missing, is not a
        regular file, escapes ``root`` via symlink or ``..``, exceeds
        ``max_bytes``, or cannot be read.
    """
    if not path.is_file() or not is_within_root(path, root):
        return None
    try:
        if path.stat().st_size > max_bytes:
            return None
        return path.read_bytes()
    except OSError:
        return None
