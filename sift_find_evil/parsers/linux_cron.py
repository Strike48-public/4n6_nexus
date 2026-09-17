"""Linux cron parser.

Parses cron entries from a mounted Linux image root into a format suitable for
the LinuxPersistenceDetector. Handles multiple cron sources with different
formats:

- /etc/crontab and /etc/cron.d/*: system format (schedule USER command)
- /var/spool/cron/crontabs/* and /var/spool/cron/*: user format (schedule command)
- /etc/cron.{hourly,daily,weekly,monthly}/*: executable scripts

Input is synthetic/in-memory fixtures representing a mounted image root; no
real evidence is read here.
"""

from __future__ import annotations

from pathlib import Path

from ._linux_fs import read_text_contained


def parse_cron_entries(root: Path) -> list[dict]:
    """Parse all cron entries from a mounted Linux image root.

    Args:
        root: Path to the mounted image root directory.

    Returns:
        A list of dicts with keys "path" (in-image absolute path) and "line"
        (the command text or script content). Comments, blank lines, and
        environment assignments are excluded.
    """
    entries: list[dict] = []

    # System cron sources (schedule USER command)
    entries.extend(_parse_system_cron(root / "etc" / "crontab", root))
    cron_d = root / "etc" / "cron.d"
    if cron_d.is_dir():
        for file_path in cron_d.iterdir():
            if file_path.is_file():
                entries.extend(_parse_system_cron(file_path, root))

    # User cron sources (schedule command, no USER field)
    for spool_base in ["var/spool/cron/crontabs", "var/spool/cron"]:
        spool_dir = root / spool_base
        if spool_dir.is_dir():
            for file_path in spool_dir.iterdir():
                if file_path.is_file():
                    entries.extend(_parse_user_cron(file_path, root))

    # Executable script directories
    for period in ["hourly", "daily", "weekly", "monthly"]:
        script_dir = root / "etc" / f"cron.{period}"
        if script_dir.is_dir():
            for script_path in script_dir.iterdir():
                if script_path.is_file():
                    entries.extend(_parse_cron_script(script_path, root))

    return entries


def _command_after_schedule(stripped: str, *, has_user_field: bool) -> str | None:
    """Return the command portion of a cron line, or None if it has none.

    Handles both the 5-field numeric schedule (``m h dom mon dow``) and the
    ``@``-prefixed special schedules (``@reboot``, ``@daily``, ...), which carry
    a SINGLE schedule token instead of five. ``@reboot`` in particular is a
    common persistence vector, so dropping it would blind the detector.

    Args:
        stripped: The whitespace-stripped cron line.
        has_user_field: True for system files (``/etc/crontab``, ``/etc/cron.d``)
            whose format inserts a USER field before the command; False for
            per-user crontabs.

    Returns:
        The command text after the schedule (and user) field(s), or None when
        the line has too few fields to carry a command.
    """
    first = stripped.split(None, 1)[0]
    if first.startswith("@"):
        n = 2 if has_user_field else 1
    else:
        n = 6 if has_user_field else 5
    fields = stripped.split(None, n)
    if len(fields) > n:
        return fields[n]
    return None


def _parse_schedule_cron(
    file_path: Path, root: Path, *, has_user_field: bool
) -> list[dict]:
    """Parse a schedule-based cron file into command-only entries.

    Args:
        file_path: Path to the cron file.
        root: Mount root to compute in-image absolute path.
        has_user_field: Whether the format carries a USER field (system cron).

    Returns:
        List of entry dicts with "path" and "line" (command only) keys.
        Comments, blank lines, and environment assignments are excluded.
    """
    content = read_text_contained(file_path, root)
    if content is None:
        return []

    in_image_path = "/" + str(file_path.relative_to(root))
    entries: list[dict] = []
    for line in content.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" in stripped.split()[0]:
            continue
        command = _command_after_schedule(stripped, has_user_field=has_user_field)
        if command is not None:
            entries.append({"path": in_image_path, "line": command})

    return entries


def _parse_system_cron(file_path: Path, root: Path) -> list[dict]:
    """Parse a system-format cron file (schedule USER command)."""
    return _parse_schedule_cron(file_path, root, has_user_field=True)


def _parse_user_cron(file_path: Path, root: Path) -> list[dict]:
    """Parse a user-format cron file (schedule command, no USER field)."""
    return _parse_schedule_cron(file_path, root, has_user_field=False)


def _parse_cron_script(script_path: Path, root: Path) -> list[dict]:
    """Parse an executable cron script (emit whole content as line).

    Args:
        script_path: Path to the script file.
        root: Mount root to compute in-image absolute path.

    Returns:
        List with single entry dict containing the script's full content as
        "line" so embedded malicious commands are detected.
    """
    content = read_text_contained(script_path, root)
    if content is None or not content.strip():
        return []

    in_image_path = "/" + str(script_path.relative_to(root))
    return [{"path": in_image_path, "line": content}]
