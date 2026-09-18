"""Tests for the Linux auth-log parser (SFE-rfhz).

Parses ``/var/log/auth.log`` (Debian/Ubuntu) and ``/var/log/secure`` (RHEL)
off a mounted image root into normalized SSH authentication events that feed
``LinuxAuthDetector``. Exercises the two log locations, the failed/accepted
event shapes, the ``invalid user`` variant, containment (missing file), and
that non-auth noise is ignored.
"""

from __future__ import annotations

import gzip
from pathlib import Path

from sift_find_evil.parsers.linux_auth import parse_auth_events


def _write(path: Path, content: str) -> None:
    """Create parent dirs and write ``content`` to ``path``."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)


def test_parses_failed_and_accepted_from_auth_log(tmp_path: Path) -> None:
    """auth.log Failed/Accepted password lines become normalized events."""
    _write(
        tmp_path / "var" / "log" / "auth.log",
        "May 10 12:00:01 host sshd[111]: Failed password for root "
        "from 203.0.113.5 port 40000 ssh2\n"
        "May 10 12:00:10 host sshd[112]: Accepted password for root "
        "from 203.0.113.5 port 40002 ssh2\n",
    )

    events = parse_auth_events(tmp_path)

    assert len(events) == 2
    failed, accepted = events
    assert failed["event"] == "failed"
    assert failed["user"] == "root"
    assert failed["source_ip"] == "203.0.113.5"
    assert accepted["event"] == "accepted"
    assert accepted["source_ip"] == "203.0.113.5"


def test_parses_invalid_user_variant(tmp_path: Path) -> None:
    """`Failed password for invalid user admin` extracts user and IP."""
    _write(
        tmp_path / "var" / "log" / "auth.log",
        "May 10 12:00:01 host sshd[111]: Failed password for invalid user "
        "admin from 198.51.100.9 port 40000 ssh2\n",
    )

    events = parse_auth_events(tmp_path)

    assert len(events) == 1
    assert events[0]["event"] == "failed"
    assert events[0]["user"] == "admin"
    assert events[0]["source_ip"] == "198.51.100.9"


def test_reads_rhel_secure_location(tmp_path: Path) -> None:
    """RHEL /var/log/secure is parsed with the same grammar as auth.log."""
    _write(
        tmp_path / "var" / "log" / "secure",
        "May 10 12:00:10 host sshd[112]: Accepted publickey for deploy "
        "from 10.0.0.5 port 50000 ssh2\n",
    )

    events = parse_auth_events(tmp_path)

    assert len(events) == 1
    assert events[0]["event"] == "accepted"
    assert events[0]["user"] == "deploy"
    assert events[0]["source_ip"] == "10.0.0.5"


def test_ignores_non_auth_lines(tmp_path: Path) -> None:
    """Non sshd-auth noise (sudo, cron, kernel) yields no events."""
    _write(
        tmp_path / "var" / "log" / "auth.log",
        "May 10 12:00:01 host sudo: pam_unix(sudo:session): session opened\n"
        "May 10 12:00:02 host CRON[999]: pam_unix(cron:session): session\n"
        "May 10 12:00:03 host kernel: [12345.6] usb 1-1: new device\n",
    )

    assert parse_auth_events(tmp_path) == []


def test_reads_rotated_and_gzipped_logs_in_chronological_order(tmp_path: Path) -> None:
    """Rotated + gzipped siblings are read oldest-first, before the current log."""
    log_dir = tmp_path / "var" / "log"
    log_dir.mkdir(parents=True)
    # Oldest rotation, gzipped.
    with gzip.open(log_dir / "auth.log.2.gz", "wt") as handle:
        handle.write(
            "Apr 01 00:00:01 host sshd[1]: Failed password for root "
            "from 203.0.113.5 port 1 ssh2\n"
        )
    # Newer rotation, plain.
    (log_dir / "auth.log.1").write_text(
        "Apr 08 00:00:01 host sshd[2]: Failed password for root "
        "from 203.0.113.5 port 2 ssh2\n"
    )
    # Current log.
    (log_dir / "auth.log").write_text(
        "Apr 15 00:00:01 host sshd[3]: Accepted password for root "
        "from 203.0.113.5 port 3 ssh2\n"
    )

    events = parse_auth_events(tmp_path)

    # Chronological: .2.gz (Apr 01) -> .1 (Apr 08) -> current (Apr 15).
    assert [e["timestamp"] for e in events] == [
        "Apr 01 00:00:01",
        "Apr 08 00:00:01",
        "Apr 15 00:00:01",
    ]
    assert [e["event"] for e in events] == ["failed", "failed", "accepted"]


def test_corrupt_gzip_is_skipped_not_fatal(tmp_path: Path) -> None:
    """A non-gzip .gz sibling degrades to a skip; other logs still parse."""
    log_dir = tmp_path / "var" / "log"
    log_dir.mkdir(parents=True)
    (log_dir / "auth.log.1.gz").write_bytes(b"this is not gzip data")
    (log_dir / "auth.log").write_text(
        "Apr 15 00:00:01 host sshd[3]: Accepted password for root "
        "from 203.0.113.5 port 3 ssh2\n"
    )

    events = parse_auth_events(tmp_path)

    assert len(events) == 1
    assert events[0]["event"] == "accepted"


def test_oversized_gzip_is_skipped(tmp_path: Path, monkeypatch) -> None:
    """A .gz whose decompressed size exceeds the cap is skipped (bomb guard)."""
    import sift_find_evil.parsers.linux_auth as mod

    monkeypatch.setattr(mod, "MAX_ARTIFACT_BYTES", 16)
    log_dir = tmp_path / "var" / "log"
    log_dir.mkdir(parents=True)
    with gzip.open(log_dir / "auth.log.1.gz", "wt") as handle:
        handle.write(
            "Apr 01 00:00:01 host sshd[1]: Failed password for root "
            "from 203.0.113.5 port 1 ssh2\n" * 10
        )

    assert parse_auth_events(tmp_path) == []


def test_missing_logs_return_empty(tmp_path: Path) -> None:
    """A root with no auth logs parses to an empty list, not an error."""
    assert parse_auth_events(tmp_path) == []
