"""Linux systemd unit file parser.

Parses systemd `.service` unit files from a mounted Linux image root directory.
Extracts ExecStart directives to feed the LinuxPersistenceDetector for malicious
command detection. Handles standard systemd locations, drop-in overrides, and
line continuations.

Input is a mounted image root containing systemd configuration; no real evidence
modification occurs.
"""

from __future__ import annotations

from pathlib import Path

from ._linux_fs import read_text_contained

# ExecStart* directives whose command text the detector inspects, in run order.
_EXEC_KEYS: tuple[str, ...] = ("ExecStartPre", "ExecStart", "ExecStartPost")


def parse_systemd_units(root: Path) -> list[dict]:
    """Parse systemd service unit files from a mounted image root.

    Walks standard systemd directories under `root` and extracts ExecStart*
    directives from `.service` files and `.service.d/*.conf` drop-ins.

    Args:
        root: Mounted image root directory containing systemd configuration
            (e.g., `/mnt/image`). Standard systemd paths are searched relative
            to this root.

    Returns:
        List of dicts with keys:
            - "path" (str): In-image absolute path (e.g., `/etc/systemd/system/foo.service`)
            - "exec_start" (str): Concatenated ExecStart* commands
    """
    systemd_dirs = [
        root / "etc" / "systemd" / "system",
        root / "lib" / "systemd" / "system",
        root / "usr" / "lib" / "systemd" / "system",
        root / "run" / "systemd" / "system",
    ]

    units: list[dict] = []
    for systemd_dir in systemd_dirs:
        if not systemd_dir.is_dir():
            continue
        units.extend(_parse_units_in_dir(systemd_dir, root))

    return units


def _parse_units_in_dir(systemd_dir: Path, root: Path) -> list[dict]:
    """Parse all .service files and drop-ins in a single systemd directory.

    Args:
        systemd_dir: Directory to scan (e.g., `/mnt/image/etc/systemd/system`).
        root: Mount root to strip for in-image paths.

    Returns:
        List of parsed unit dicts.
    """
    units: list[dict] = []

    # Parse .service files
    for service_file in systemd_dir.glob("*.service"):
        if service_file.is_file():
            unit = _parse_unit_file(service_file, root)
            if unit:
                units.append(unit)

    # Parse .service.d/*.conf drop-ins
    for dropin_dir in systemd_dir.glob("*.service.d"):
        if dropin_dir.is_dir():
            for conf_file in dropin_dir.glob("*.conf"):
                if conf_file.is_file():
                    unit = _parse_unit_file(conf_file, root)
                    if unit:
                        units.append(unit)

    return units


def _parse_unit_file(unit_path: Path, root: Path) -> dict | None:
    """Parse a single systemd unit file.

    Uses a hand-rolled ``[Section] key=value`` scan rather than
    ``configparser``: systemd allows REPEATED ``ExecStart=`` lines (all run, in
    order) which configparser would collapse to the last, and unit values carry
    ``%``-specifiers (``%i``, ``%h``) that configparser would try to
    interpolate and choke on.

    Args:
        unit_path: Path to .service or .conf file.
        root: Mount root to strip for in-image path.

    Returns:
        Dict with "path" and "exec_start" keys, or None if the file escapes the
        root, is unreadable, or has no ExecStart* directives.
    """
    content = read_text_contained(unit_path, root)
    if content is None:
        return None

    content = _resolve_line_continuations(content)
    exec_commands = _extract_exec_commands(content)
    if not exec_commands:
        return None

    in_image_path = "/" + str(unit_path.relative_to(root))
    return {
        "path": in_image_path,
        "exec_start": " ".join(exec_commands),
    }


def _resolve_line_continuations(content: str) -> str:
    """Resolve line continuations (backslash at end of line).

    Args:
        content: Raw unit file content.

    Returns:
        Content with line continuations resolved.
    """
    lines = content.splitlines()
    resolved: list[str] = []

    i = 0
    while i < len(lines):
        line = lines[i]
        if line.rstrip().endswith("\\"):
            # Accumulate continued lines
            continued = line.rstrip()[:-1]  # Remove trailing backslash
            i += 1
            while i < len(lines) and lines[i - 1].rstrip().endswith("\\"):
                continued += " " + lines[i].strip()
                i += 1
            if i < len(lines):
                continued += " " + lines[i].strip()
            resolved.append(continued)
        else:
            resolved.append(line)
        i += 1

    return "\n".join(resolved)


def _extract_exec_commands(content: str) -> list[str]:
    """Extract every ExecStart* command from the [Service] section.

    Collects ALL matching directives (systemd runs repeated ExecStart lines in
    sequence), preserving file order so a malicious command hidden among benign
    ones is not lost.

    Args:
        content: Unit file text with line continuations already resolved.

    Returns:
        List of exec command strings in the order they appear.
    """
    commands: list[str] = []
    in_service = False
    for raw in content.splitlines():
        line = raw.strip()
        if line.startswith("[") and line.endswith("]"):
            in_service = line[1:-1].strip().lower() == "service"
            continue
        if not in_service or "=" not in line:
            continue
        key, _, value = line.partition("=")
        if key.strip() in _EXEC_KEYS and value.strip():
            commands.append(value.strip())
    return commands
