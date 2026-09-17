"""Linux sudoers parser.

Parses /etc/sudoers and /etc/sudoers.d/* files from a mounted image root into
the input contract expected by ``LinuxPersistenceDetector``. Handles include
directives (#includedir, @includedir, #include) and line-continuation
backslashes.

Input is a mounted filesystem root; output is a list of dicts with keys
"path" (in-image absolute path) and "line" (raw sudoers directive). No real
evidence is mutated.
"""

from __future__ import annotations

from pathlib import Path

from ._linux_fs import read_text_contained


def parse_sudoers(root: Path) -> list[dict]:
    """Parse sudoers configuration from a mounted image root.

    Reads /etc/sudoers and recursively processes #includedir, @includedir,
    and #include directives. Handles line-continuation backslashes (a trailing
    backslash joins the next line to the current one).

    Args:
        root: Mounted image root directory containing /etc/sudoers.

    Returns:
        A list of dicts, each with keys "path" (in-image absolute path, e.g.
        "/etc/sudoers.d/custom") and "line" (raw sudoers text). Empty lines
        are skipped. The list preserves file order: main file first, then
        includes in discovery order.
    """
    main_file = root / "etc" / "sudoers"
    if not main_file.exists():
        return []

    entries: list[dict] = []
    visited: set[Path] = set()
    _parse_file(main_file, root, entries, visited)
    return entries


def _parse_file(
    file_path: Path, root: Path, entries: list[dict], visited: set[Path]
) -> None:
    """Parse a single sudoers file, appending entries and processing includes.

    Args:
        file_path: Absolute path to the sudoers file on disk.
        root: Mounted image root (for stripping prefix to get in-image path).
        entries: Accumulator list to append parsed entries to.
        visited: Resolved paths already parsed, guarding against include cycles
            (a self- or mutually-referential ``#include`` on a real image would
            otherwise recurse without bound).
    """
    if not file_path.exists():
        return

    # Cycle guard: a real mounted image can contain attacker-controlled includes.
    resolved = _safe_resolve(file_path)
    if resolved is None or resolved in visited:
        return
    visited.add(resolved)

    # Containment + safe read: never read outside the mounted evidence root
    # (traversal via `#include ../../etc/passwd` or a symlink), and degrade a
    # binary/oversized file to a skip rather than crashing the run.
    content = read_text_contained(file_path, root)
    if content is None:
        return

    in_image_path = "/" + str(file_path.relative_to(root)).replace("\\", "/")
    lines = _join_continuation(content)

    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue

        # Add the line to entries (detector will filter as needed)
        entries.append({"path": in_image_path, "line": line})

        # Detect and process include directives
        if stripped.startswith("#includedir ") or stripped.startswith("@includedir "):
            dir_path_str = stripped.split(None, 1)[1]
            _parse_includedir(root, dir_path_str, entries, visited)
        elif stripped.startswith("#include "):
            include_path_str = stripped.split(None, 1)[1]
            include_abs = _resolve_include_path(root, include_path_str)
            _parse_file(include_abs, root, entries, visited)


def _safe_resolve(path: Path) -> Path | None:
    """Resolve a path to its canonical form, or None if it cannot be resolved."""
    try:
        return path.resolve()
    except (OSError, RuntimeError):
        return None


def _join_continuation(content: str) -> list[str]:
    """Join lines ending with a backslash continuation into logical lines.

    Args:
        content: Raw file text.

    Returns:
        A list of logical lines (with backslash continuations resolved).
    """
    raw_lines = content.splitlines()
    joined: list[str] = []
    current: list[str] = []

    for line in raw_lines:
        if line.endswith("\\"):
            # Remove trailing backslash and accumulate
            current.append(line[:-1])
        else:
            # End of continuation
            current.append(line)
            joined.append("".join(current))
            current = []

    # If file ended with a backslash, flush remaining
    if current:
        joined.append("".join(current))

    return joined


def _parse_includedir(
    root: Path, dir_path_str: str, entries: list[dict], visited: set[Path]
) -> None:
    """Parse all files in a sudoers include directory.

    Args:
        root: Mounted image root.
        dir_path_str: Directory path string (e.g. "/etc/sudoers.d").
        entries: Accumulator list to append parsed entries to.
        visited: Resolved paths already parsed (include-cycle guard).
    """
    dir_abs = _resolve_include_path(root, dir_path_str)
    if not dir_abs.exists() or not dir_abs.is_dir():
        return

    # Process files in sorted order for determinism
    for child in sorted(dir_abs.iterdir()):
        if child.is_file():
            _parse_file(child, root, entries, visited)


def _resolve_include_path(root: Path, path_str: str) -> Path:
    """Resolve an include path relative to the image root.

    Args:
        root: Mounted image root.
        path_str: Path string from an include directive (may be relative).

    Returns:
        Absolute path on the host filesystem.
    """
    # Strip leading slash if present to make it relative to root
    if path_str.startswith("/"):
        path_str = path_str[1:]
    return root / path_str
