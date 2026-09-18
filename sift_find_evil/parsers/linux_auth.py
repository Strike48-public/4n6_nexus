"""Linux authentication-log parser (SFE-rfhz).

Parses SSH authentication events from a mounted image root's system auth log:

- ``/var/log/auth.log`` (Debian/Ubuntu family)
- ``/var/log/secure`` (RHEL/Fedora family)

Both use the same ``sshd`` syslog grammar, so one line grammar covers both.
Only ``Failed password`` and ``Accepted <method>`` sshd lines are extracted;
every other syslog line (sudo, cron, kernel) is ignored. Each event is
normalized to ``{"raw", "timestamp", "event", "user", "source_ip", "port"}``
so the downstream ``LinuxAuthDetector`` can reason about brute-force sequences
without re-parsing text.

Input is a mounted image root -- attacker-controlled content -- so reads go
through :func:`read_text_contained` for symlink-escape and size protection.
The mounted root is never mutated.
"""

from __future__ import annotations

import gzip
import re
from pathlib import Path
from typing import Optional

from ._linux_fs import MAX_ARTIFACT_BYTES, is_within_root, read_text_contained
from ._sshd import SSHD_AUTH_BODY

# sshd auth lines look like:
#   May 10 12:00:01 host sshd[111]: Failed password for root from 203.0.113.5 port 40000 ssh2
#   May 10 12:00:10 host sshd[112]: Accepted publickey for deploy from 10.0.0.5 port 50000 ssh2
#   May 10 12:00:01 host sshd[111]: Failed password for invalid user admin from 198.51.100.9 port 40000 ssh2
# A syslog timestamp + host + ``sshd[pid]:`` prefix framing the shared sshd
# message body (single-sourced in ``_sshd.SSHD_AUTH_BODY`` so this surface and
# the journald surface cannot drift on what an sshd auth event looks like).
_AUTH_LINE = re.compile(
    r"^(?P<timestamp>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+"
    r"\S+\s+sshd\[\d+\]:\s+" + SSHD_AUTH_BODY,
)

# Base names of the auth logs we read, under /var/log. Rotated siblings
# (auth.log.1, auth.log.2.gz, secure-20260801 ...) are discovered per base.
_AUTH_LOG_DIR: tuple[str, ...] = ("var", "log")
_AUTH_LOG_BASES: tuple[str, ...] = ("auth.log", "secure")

# On dead-disk evidence the *current* log holds only recent activity; an
# intrusion from weeks ago lives in a rotated (and usually gzipped) sibling, so
# recall depends on reading those too.
_NUMBERED_SUFFIX = re.compile(r"\.(\d+)(?:\.gz)?$")


def _rotation_sort_key(path: Path) -> tuple:
    """Sort a base log's rotated siblings oldest-first.

    logrotate names newer rotations with smaller numbers (``auth.log.1`` is
    newer than ``auth.log.2``), so a higher number is older. Date-suffixed
    names (``secure-20260801``) sort chronologically by name. Oldest first
    keeps the concatenated event stream in chronological order, which the
    detector's temporal reasoning relies on. The leading bucket flag keeps the
    two naming schemes from being compared against each other.
    """
    match = _NUMBERED_SUFFIX.search(path.name)
    if match:
        # Negate so the largest (oldest) number sorts first.
        return (0, -int(match.group(1)))
    return (1, path.name)


def _read_log(path: Path, root: Path) -> Optional[str]:
    """Read a plain or gzipped auth log, contained within ``root``.

    gzip members are decompressed with a decompressed-size cap so a compression
    bomb degrades to a skip rather than exhausting memory. Plain files defer to
    :func:`read_text_contained`.
    """
    if path.suffix == ".gz":
        if not path.is_file() or not is_within_root(path, root):
            return None
        try:
            with gzip.open(path, "rt", encoding="utf-8", errors="replace") as handle:
                data = handle.read(MAX_ARTIFACT_BYTES + 1)
        except (OSError, EOFError, gzip.BadGzipFile):
            return None
        return None if len(data) > MAX_ARTIFACT_BYTES else data
    return read_text_contained(path, root)


def _auth_log_paths(root: Path) -> list[Path]:
    """Enumerate current + rotated auth logs in chronological (oldest) order."""
    log_dir = root.joinpath(*_AUTH_LOG_DIR)
    if not log_dir.is_dir():
        return []
    paths: list[Path] = []
    for base in _AUTH_LOG_BASES:
        current = log_dir / base
        rotated = [p for p in log_dir.glob(f"{base}*") if p != current and p.is_file()]
        rotated.sort(key=_rotation_sort_key)
        paths.extend(rotated)  # oldest rotations first
        if current.is_file():
            paths.append(current)  # newest last
    return paths


def parse_auth_events(root: Path) -> list[dict]:
    """Parse SSH authentication events from a mounted image root.

    Reads the current logs and their rotated siblings (``auth.log.1``,
    ``auth.log.2.gz``, ``secure-YYYYMMDD`` ...) so an intrusion recorded before
    the last rotation is still seen. Files are read oldest-first so the event
    stream stays chronological.

    Args:
        root: Mounted image root directory containing the filesystem tree.

    Returns:
        A list of normalized event dicts in chronological order, one per matched
        sshd ``Failed``/``Accepted`` line. Each dict has ``"raw"``,
        ``"timestamp"``, ``"event"`` (``"failed"`` or ``"accepted"``),
        ``"user"``, ``"source_ip"`` and ``"port"``. Missing logs yield an empty
        list rather than an error. The input directory is never mutated.
    """
    events: list[dict] = []
    for path in _auth_log_paths(root):
        content = _read_log(path, root)
        if content is None:
            continue
        for line in content.splitlines():
            match = _AUTH_LINE.match(line)
            if match is None:
                continue
            events.append(
                {
                    "raw": line,
                    "timestamp": match.group("timestamp"),
                    "event": match.group("event").lower(),
                    "user": match.group("user"),
                    "source_ip": match.group("source_ip"),
                    "port": match.group("port"),
                }
            )
    return events
