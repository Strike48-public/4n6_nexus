"""Linux artifact collector.

Walks a mounted image root (or a live-response bundle laid out like a root
filesystem) and invokes the per-artifact Linux parsers to assemble the exact
input contract of :class:`~sift_find_evil.detectors.linux_persistence.LinuxPersistenceDetector`.

This is the seam that turns a *real dead-disk image* into detector findings:
before it, both the CLI ``--linux-artifacts`` path and the scenario harness
consumed a hand-authored JSON bundle already shaped like the detector's dict.
The collector produces that same dict from raw ``.service`` units, crontabs,
``sudoers`` files, ``/etc/ld.so.preload`` and shell-init files instead.

The collector is read-only over the mounted root and never mutates its inputs.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Optional

from .linux_auth import parse_auth_events
from .linux_cron import parse_cron_entries
from .linux_history import parse_shell_history
from .linux_journald import parse_journald
from .linux_proc import parse_proc_processes
from .linux_shell import parse_ld_preload, parse_shell_init
from .linux_sudoers import parse_sudoers
from .linux_systemd import parse_systemd_units
from .linux_wtmp import parse_login_sessions

_MONTHS = {
    m: i
    for i, m in enumerate(
        (
            "jan",
            "feb",
            "mar",
            "apr",
            "may",
            "jun",
            "jul",
            "aug",
            "sep",
            "oct",
            "nov",
            "dec",
        ),
        start=1,
    )
}


def _syslog_ts_tuple(raw: str) -> Optional[tuple[int, int, int, int, int]]:
    """Parse a syslog ``%b %e %H:%M:%S`` string to ``(mon, day, h, m, s)``.

    Year-independent (syslog omits the year) and space/zero-pad agnostic, so an
    auth.log timestamp and a journald timestamp rendered from the same instant
    compare equal. Returns None when the string is not a syslog timestamp.
    """
    parts = raw.split()
    if len(parts) < 3:
        return None
    month = _MONTHS.get(parts[0].lower())
    hms = parts[2].split(":")
    if month is None or len(hms) != 3:
        return None
    try:
        return (month, int(parts[1]), int(hms[0]), int(hms[1]), int(hms[2]))
    except ValueError:
        return None


def _auth_event_key(event: dict[str, Any]) -> tuple:
    """Cross-surface identity of one auth event, for dedupe.

    Two events are the same real-world sshd attempt when their event kind,
    account, source IP, port and second-resolution timestamp match -- so a host
    logging the same attempt to both auth.log and the journal is counted once
    (which stops a duplicated failed-attempt flood from inflating the
    brute-force count past its threshold).
    """
    return (
        event.get("event"),
        event.get("user"),
        event.get("source_ip"),
        event.get("port"),
        _syslog_ts_tuple(str(event.get("timestamp") or "")),
    )


def _merge_auth_events(
    authlog: list[dict[str, Any]], journald: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Merge journald auth events into the auth.log stream, deduped and ordered.

    journald events that are exact duplicates of an auth.log event are dropped;
    the rest are merged in. ``LinuxAuthDetector`` counts failures *before* the
    first accepted login per ``(ip, user)`` pair, so the merged stream MUST stay
    chronological -- otherwise a pair whose events are split across both surfaces
    (e.g. auth.log holds the ``Accepted`` while journald holds earlier
    ``Failed`` attempts that did not exact-dedupe) would put the success first
    and silently under-count, missing a real compromise.

    When journald contributes nothing new (no dump, or every event deduped) the
    auth.log stream is returned untouched, so the auth.log-only path keeps its
    exact file order (year-aware across log rotations). Only when journald adds
    events is the stream sorted by second-resolution timestamp; that key omits
    the year (syslog does), so a both-surfaces pair spanning a calendar-year
    boundary is the one residual ordering limitation.
    """
    seen = {_auth_event_key(e) for e in authlog}
    extra = [e for e in journald if _auth_event_key(e) not in seen]
    if not extra:
        return authlog
    merged = authlog + extra
    merged.sort(key=_auth_sort_key)
    return merged


def _auth_sort_key(event: dict[str, Any]) -> tuple:
    """Chronological sort key for an auth event; undated events sort last."""
    ts = _syslog_ts_tuple(str(event.get("timestamp") or ""))
    return (ts is None, ts or (0, 0, 0, 0, 0))


def _merge_login_sessions(
    wtmp: list[dict[str, Any]], journald: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Merge journald login sessions into the wtmp stream, deduped.

    A journald ``Accepted`` login for a ``(user, source_ip)`` pair already
    recorded by wtmp is dropped -- the wtmp binary record is richer (it carries
    the tty and exact time). The login detector also dedupes by pair, so this
    coarse dedupe only avoids a redundant journald session shadowing the wtmp
    one; it can never double-report.
    """
    seen = {(s.get("user"), s.get("source_ip")) for s in wtmp}
    extra = [s for s in journald if (s.get("user"), s.get("source_ip")) not in seen]
    return wtmp + extra


def collect_linux_artifacts(root: Path) -> dict[str, Any]:
    """Collect Linux persistence artifacts from a mounted image root.

    Args:
        root: Path to a mounted image root (or a live-response bundle laid out
            like a root filesystem). Missing artifact sources yield empty
            values rather than errors, so a partial collection still runs.

    Returns:
        A new dict matching the ``LinuxPersistenceDetector`` contract (keys
        ``systemd_units``, ``cron_entries``, ``ld_preload``, ``sudoers``,
        ``bashrc_entries``) plus ``auth_events`` for ``LinuxAuthDetector``,
        ``shell_history`` for ``LinuxExecutionDetector``, ``login_sessions``
        for ``LinuxLoginSessionDetector`` and ``proc_processes`` for
        ``LinuxProcessDetector``. The mounted root is never modified.

        The ``auth_events`` and ``login_sessions`` streams merge the auth.log /
        wtmp surfaces with any captured journald dump (``parse_journald``),
        cross-surface-deduped so a host logging to both syslog and the journal
        is not double-counted.
    """
    journald = parse_journald(root)
    return {
        "systemd_units": parse_systemd_units(root),
        "cron_entries": parse_cron_entries(root),
        "ld_preload": parse_ld_preload(root),
        "sudoers": parse_sudoers(root),
        "bashrc_entries": parse_shell_init(root),
        "auth_events": _merge_auth_events(
            parse_auth_events(root), journald["auth_events"]
        ),
        "shell_history": parse_shell_history(root),
        "login_sessions": _merge_login_sessions(
            parse_login_sessions(root), journald["login_sessions"]
        ),
        "proc_processes": parse_proc_processes(root),
    }
