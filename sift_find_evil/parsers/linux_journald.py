"""Linux journald export parser (SFE-4igf, Tranche-2 of SFE-4fnv).

Systemd hosts that run *without* rsyslog have no ``/var/log/auth.log`` -- the
systemd journal is the only record of who authenticated. The native journal
(``/var/log/journal/**/*.journal``) is a binary object-store (hash tables, LZ4
compression) that is out of scope; instead this parser ingests a **captured
text dump** a responder produces with ``journalctl -o json`` (JSON Lines, the
primary and most robust form) or ``journalctl -o export`` (the field=value
export format). Both carry the same journal fields, so one normalizer serves
both readers.

Only sshd ``Failed``/``Accepted`` records are extracted (the shared grammar in
:mod:`._sshd`), normalized into the **same** ``auth_events`` dicts that
:func:`~sift_find_evil.parsers.linux_auth.parse_auth_events` emits and, for each
``Accepted`` login, a ``login_sessions`` dict shaped like
:func:`~sift_find_evil.parsers.linux_wtmp.parse_login_sessions`. The collector
then merges and dedupes these against the auth.log / wtmp surfaces so a host
logging to both syslog and the journal is never double-counted.

The dump is attacker-controlled evidence on a mounted image root, so the read
routes through :func:`~sift_find_evil.parsers._linux_fs.read_text_contained`
(symlink-escape containment + size cap) and every record decode is defensive: a
malformed line/block is skipped, never fatal. The mounted root is never
mutated.

**Operator note -- cross-surface dedupe timezone bound.** The collector dedupes
these events against auth.log by a second-resolution timestamp key. journald
timestamps are rendered in **UTC** (journal realtime is UTC); auth.log syslog
timestamps carry no timezone and are written in the host's *local* time. When a
host logs sshd to BOTH the journal and a non-UTC-local auth.log, the same real
event carries different wall-clock strings on each surface and will NOT dedupe,
so it appears twice in the merged stream. The bounded effect is a possibly
*inflated* failure count (over-detection) -- a benign near-threshold login on
such a host could be flagged. Because the merged stream is sorted
chronologically, this does NOT under-count (miss a compromise) within a
calendar year; the one residual ordering limitation is a both-surfaces pair
whose events span a year boundary (the syslog timestamp omits the year).
Uniform-logging hosts (both UTC, or journal-only, or auth.log-only) are exact.
Timezone-aware dedupe is deferred as a follow-up; over-detection is the
forensically safer failure mode.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Optional

from ._linux_fs import read_text_contained
from ._sshd import parse_sshd_auth_message

# Conventional relative paths a live-response bundle drops a journalctl capture
# into, probed in order (mirrors ``linux_wtmp._LOGIN_SOURCES``). The native
# binary ``*.journal`` files are intentionally NOT listed -- they are out of
# scope. A ``.json`` capture is JSON Lines; ``.export`` is the export format;
# format is autodetected by content, so the suffix is only a discovery hint.
_JOURNALD_SOURCES: tuple[str, ...] = (
    "var/log/journal/journalctl.json",
    "var/log/journal/journalctl.export",
    "var/log/journalctl.json",
    "var/log/journalctl.export",
    "journald.json",
    "journald.export",
)

# journal fields we read. Any other field (and the export format's binary-value
# framing) is ignored, so a hostile capture cannot inject unexpected state.
_F_MESSAGE = "MESSAGE"
_F_IDENT = "SYSLOG_IDENTIFIER"
_F_COMM = "_COMM"
_F_REALTIME = "__REALTIME_TIMESTAMP"
_F_HOSTNAME = "_HOSTNAME"


def _is_sshd(record: dict[str, str]) -> bool:
    """True when the record originates from sshd (identifier or _COMM).

    OpenSSH 9.8+ splits the listener into ``sshd-session``, so a prefix match on
    ``sshd`` covers both the classic ``sshd`` identifier and the split process.
    """
    for value in (record.get(_F_IDENT, ""), record.get(_F_COMM, "")):
        if value == "sshd" or value.startswith("sshd"):
            return True
    return False


def _realtime_seconds(record: dict[str, str]) -> Optional[int]:
    """Parse ``__REALTIME_TIMESTAMP`` (microseconds since epoch) to seconds."""
    raw = record.get(_F_REALTIME, "")
    try:
        return int(raw) // 1_000_000
    except (TypeError, ValueError):
        return None


def _syslog_timestamp(epoch_seconds: Optional[int]) -> str:
    """Render epoch seconds as a syslog ``%b %d %H:%M:%S`` string (UTC).

    Kept in the same textual shape auth.log events carry so a journald event and
    its auth.log twin normalize to the same dedupe key. UTC is deliberate and
    documented: cross-surface dedupe is exact when both logs share a wall clock
    (journald realtime is UTC; the collector authors fixtures UTC). A host whose
    auth.log is in local time may fail to dedupe some events -- the bounded
    effect is a possibly-inflated failure count, never a missed compromise.
    """
    if epoch_seconds is None:
        return ""
    return time.strftime("%b %d %H:%M:%S", time.gmtime(epoch_seconds))


def _iter_json_records(text: str) -> list[dict[str, str]]:
    """Parse JSON Lines (``journalctl -o json``): one object per line.

    Non-string field values (journal renders binary/multivalued fields as
    arrays or numbers) are coerced to ``str`` so the downstream grammar sees a
    consistent type; an unparseable line is skipped, never fatal.
    """
    records: list[dict[str, str]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except (ValueError, TypeError):
            continue
        if isinstance(obj, dict):
            records.append({str(k): _as_text(v) for k, v in obj.items()})
    return records


def _iter_export_records(text: str) -> list[dict[str, str]]:
    """Parse the export format (``journalctl -o export``): field=value blocks.

    Entries are separated by a blank line; within an entry each ``FIELD=value``
    line contributes a field. A line without ``=`` is the export format's
    binary-value framing (a length-prefixed raw blob) -- after a text decode
    that framing is unreliable, so such lines are skipped. Only the known text
    fields we read matter, so skipping binary framing loses nothing for sshd
    auth records (whose MESSAGE is plain ASCII).
    """
    records: list[dict[str, str]] = []
    current: dict[str, str] = {}
    for line in text.splitlines():
        if line == "":
            if current:
                records.append(current)
                current = {}
            continue
        if "=" in line:
            field, value = line.split("=", 1)
            current[field] = value
    if current:
        records.append(current)
    return records


def _as_text(value: Any) -> str:
    """Coerce a JSON field value to text (arrays -> first element, else str)."""
    if isinstance(value, str):
        return value
    if isinstance(value, list) and value:
        return _as_text(value[0])
    return "" if value is None else str(value)


def _parse_records(text: str) -> list[dict[str, str]]:
    """Autodetect the dump format by content and parse to field dicts.

    A dump with any ``{``-leading line is JSON Lines (export ``FIELD=value``
    lines never start with ``{``); anything else is the export format. Scanning
    for the signal rather than trusting the first line means a leading garbage
    line does not misroute detection.
    """
    is_json = any(line.strip().startswith("{") for line in text.splitlines())
    return _iter_json_records(text) if is_json else _iter_export_records(text)


def parse_journald(root: Path) -> dict[str, list[dict[str, Any]]]:
    """Parse sshd auth events + login sessions from a journalctl dump.

    Args:
        root: Mounted image root (or a live-response bundle laid out like a root
            filesystem). The first conventional capture path that exists is
            read; missing captures yield empty lists rather than an error.

    Returns:
        ``{"auth_events": [...], "login_sessions": [...]}``. ``auth_events`` are
        shaped like :func:`~sift_find_evil.parsers.linux_auth.parse_auth_events`
        (``raw``/``timestamp``/``event``/``user``/``source_ip``/``port``) plus a
        ``source`` provenance key of ``"journald"``, in journal (chronological)
        order. ``login_sessions`` are shaped like
        :func:`~sift_find_evil.parsers.linux_wtmp.parse_login_sessions`, one per
        ``Accepted`` login. The mounted root is never modified.
    """
    text: Optional[str] = None
    source_path = ""
    for rel in _JOURNALD_SOURCES:
        candidate = read_text_contained(root / rel, root)
        if candidate is not None:
            text = candidate
            source_path = f"/{rel}"
            break
    if text is None:
        return {"auth_events": [], "login_sessions": []}

    records = _parse_records(text)
    # Chronological order: the auth detector's brute-force temporal reasoning
    # and the merge's stable ordering both rely on it. Records without a
    # timestamp sort last (stable).
    records.sort(
        key=lambda r: (_realtime_seconds(r) is None, _realtime_seconds(r) or 0)
    )

    auth_events: list[dict[str, Any]] = []
    login_sessions: list[dict[str, Any]] = []
    for record in records:
        if not _is_sshd(record):
            continue
        parsed = parse_sshd_auth_message(record.get(_F_MESSAGE, ""))
        if parsed is None:
            continue
        epoch = _realtime_seconds(record)
        timestamp = _syslog_timestamp(epoch)
        auth_events.append(
            {
                "raw": record.get(_F_MESSAGE, ""),
                "timestamp": timestamp,
                "event": parsed["event"],
                "user": parsed["user"],
                "source_ip": parsed["source_ip"],
                "port": parsed["port"],
                "source": "journald",
            }
        )
        if parsed["event"] == "accepted":
            login_sessions.append(
                {
                    "user": parsed["user"],
                    "line": "",
                    "host": record.get(_F_HOSTNAME, ""),
                    "source_ip": parsed["source_ip"],
                    "timestamp": epoch,
                    "source_path": source_path,
                    "source": "journald",
                }
            )
    return {"auth_events": auth_events, "login_sessions": login_sessions}
