"""Tests for the Linux journald export parser + collector merge (SFE-4igf).

The parser ingests a captured ``journalctl -o json`` (JSON Lines) or
``journalctl -o export`` dump off a mounted image root and normalizes sshd
``Failed``/``Accepted`` records into the same ``auth_events`` / ``login_sessions``
dicts the auth.log and wtmp surfaces produce. The collector then merges and
cross-surface-dedupes them so a host logging to both syslog and the journal is
not double-counted.

Covered: JSON + export readers, format autodetect, sshd gating, the two event
shapes, provenance stamping, containment/skip, and -- the main correctness
guard -- the both-surfaces dedupe that must not inflate the brute-force count.
"""

from __future__ import annotations

import json
from pathlib import Path

from sift_find_evil.detectors import LinuxAuthDetector, LinuxLoginSessionDetector
from sift_find_evil.parsers import collect_linux_artifacts
from sift_find_evil.parsers.linux_collector import _syslog_ts_tuple
from sift_find_evil.parsers.linux_journald import parse_journald

# A genuine public IP (NOT an RFC-5737 doc range) so the external-login guard in
# LinuxLoginSessionDetector fires rather than passing vacuously.
_PUBLIC_IP = "45.83.122.10"


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _json_line(message: str, *, ident: str = "sshd", micros: int = 0) -> str:
    """One ``journalctl -o json`` record line."""
    return json.dumps(
        {
            "__REALTIME_TIMESTAMP": str(micros),
            "SYSLOG_IDENTIFIER": ident,
            "_COMM": ident,
            "_HOSTNAME": "victim",
            "MESSAGE": message,
        }
    )


def _failed(ip: str, user: str, port: int, micros: int) -> str:
    return _json_line(
        f"Failed password for {user} from {ip} port {port} ssh2", micros=micros
    )


def _accepted(ip: str, user: str, port: int, micros: int) -> str:
    return _json_line(
        f"Accepted password for {user} from {ip} port {port} ssh2", micros=micros
    )


def _write_journal_json(root: Path, lines: list[str]) -> None:
    _write(root / "var/log/journal/journalctl.json", "\n".join(lines) + "\n")


# --- parser: format readers + normalization -------------------------------


def test_json_reader_normalizes_failed_and_accepted(tmp_path: Path) -> None:
    _write_journal_json(
        tmp_path,
        [
            _failed(_PUBLIC_IP, "root", 40000, 1_000_000),
            _accepted(_PUBLIC_IP, "root", 40001, 2_000_000),
        ],
    )

    result = parse_journald(tmp_path)

    assert [e["event"] for e in result["auth_events"]] == ["failed", "accepted"]
    failed = result["auth_events"][0]
    assert failed["user"] == "root"
    assert failed["source_ip"] == _PUBLIC_IP
    assert failed["source"] == "journald"
    # The Accepted login also yields a login_session for the T1078 surface.
    assert len(result["login_sessions"]) == 1
    session = result["login_sessions"][0]
    assert session["user"] == "root"
    assert session["source_ip"] == _PUBLIC_IP
    assert session["source"] == "journald"
    assert session["timestamp"] == 2  # 2_000_000 micros -> 2 seconds


def test_export_format_is_parsed(tmp_path: Path) -> None:
    """``journalctl -o export`` field=value blocks parse like the JSON form."""
    _write(
        tmp_path / "var/log/journal/journalctl.export",
        "__REALTIME_TIMESTAMP=1000000\n"
        "SYSLOG_IDENTIFIER=sshd\n"
        f"MESSAGE=Accepted publickey for root from {_PUBLIC_IP} port 22 ssh2\n"
        "\n",
    )

    result = parse_journald(tmp_path)

    assert len(result["auth_events"]) == 1
    assert result["auth_events"][0]["event"] == "accepted"
    assert result["login_sessions"][0]["source_ip"] == _PUBLIC_IP


def test_records_sorted_chronologically(tmp_path: Path) -> None:
    """Out-of-order records are returned oldest-first (temporal guard)."""
    _write_journal_json(
        tmp_path,
        [
            _failed(_PUBLIC_IP, "root", 3, 3_000_000),
            _failed(_PUBLIC_IP, "root", 1, 1_000_000),
            _failed(_PUBLIC_IP, "root", 2, 2_000_000),
        ],
    )

    ports = [e["port"] for e in parse_journald(tmp_path)["auth_events"]]

    assert ports == ["1", "2", "3"]


def test_sshd_session_split_comm_is_recognized(tmp_path: Path) -> None:
    """OpenSSH 9.8+ ``sshd-session`` identifier still counts as sshd."""
    _write(
        tmp_path / "var/log/journal/journalctl.json",
        json.dumps(
            {
                "__REALTIME_TIMESTAMP": "1000000",
                "SYSLOG_IDENTIFIER": "sshd-session",
                "MESSAGE": f"Accepted password for root from {_PUBLIC_IP} port 22 ssh2",
            }
        )
        + "\n",
    )

    result = parse_journald(tmp_path)

    assert len(result["auth_events"]) == 1


def test_non_sshd_and_non_auth_records_ignored(tmp_path: Path) -> None:
    """systemd / cron / non-auth sshd noise yields no events."""
    _write_journal_json(
        tmp_path,
        [
            _json_line("Started Session 1 of user root.", ident="systemd"),
            _json_line("pam_unix(cron:session): session opened", ident="CRON"),
            _json_line("Server listening on 0.0.0.0 port 22.", ident="sshd"),
        ],
    )

    result = parse_journald(tmp_path)

    assert result == {"auth_events": [], "login_sessions": []}


def test_malformed_lines_are_skipped_not_fatal(tmp_path: Path) -> None:
    """A garbage JSON line is skipped; valid records still parse."""
    _write(
        tmp_path / "var/log/journal/journalctl.json",
        "this is not json\n" + _accepted(_PUBLIC_IP, "root", 22, 1_000_000) + "\n",
    )

    assert len(parse_journald(tmp_path)["auth_events"]) == 1


def test_missing_dump_returns_empty(tmp_path: Path) -> None:
    assert parse_journald(tmp_path) == {"auth_events": [], "login_sessions": []}


def test_syslog_ts_tuple_parses_and_rejects() -> None:
    """The dedupe timestamp parser is pad-agnostic and rejects malformed input."""
    assert _syslog_ts_tuple("May 10 12:00:01") == (5, 10, 12, 0, 1)
    assert _syslog_ts_tuple("Apr  1 09:08:07") == (4, 1, 9, 8, 7)  # space-padded day
    assert _syslog_ts_tuple("") is None  # too few parts
    assert _syslog_ts_tuple("Xyz 10 12:00:01") is None  # bad month
    assert _syslog_ts_tuple("May 10 12:00") is None  # incomplete HMS
    assert _syslog_ts_tuple("May ab 12:00:01") is None  # non-numeric day


def test_message_as_array_is_coerced(tmp_path: Path) -> None:
    """A journal MESSAGE rendered as an array (multivalued) is coerced to text."""
    _write(
        tmp_path / "var/log/journal/journalctl.json",
        json.dumps(
            {
                "__REALTIME_TIMESTAMP": "1000000",
                "SYSLOG_IDENTIFIER": "sshd",
                "MESSAGE": [
                    f"Accepted password for root from {_PUBLIC_IP} port 22 ssh2"
                ],
            }
        )
        + "\n",
    )

    assert len(parse_journald(tmp_path)["auth_events"]) == 1


def test_non_numeric_timestamp_yields_empty_timestamp(tmp_path: Path) -> None:
    """A record with a non-numeric realtime still parses; timestamp is blank."""
    _write(
        tmp_path / "var/log/journal/journalctl.json",
        json.dumps(
            {
                "__REALTIME_TIMESTAMP": "not-a-number",
                "SYSLOG_IDENTIFIER": "sshd",
                "MESSAGE": f"Failed password for root from {_PUBLIC_IP} port 22 ssh2",
            }
        )
        + "\n",
    )

    # Routed through the collector so the merge's dedupe key handles the blank ts.
    events = collect_linux_artifacts(tmp_path)["auth_events"]

    assert len(events) == 1
    assert events[0]["timestamp"] == ""


def test_export_without_trailing_blank_line(tmp_path: Path) -> None:
    """The final export block flushes even without a trailing blank line."""
    _write(
        tmp_path / "var/log/journal/journalctl.export",
        "__REALTIME_TIMESTAMP=1000000\n"
        "SYSLOG_IDENTIFIER=sshd\n"
        f"MESSAGE=Failed password for root from {_PUBLIC_IP} port 22 ssh2\n",
    )

    assert len(parse_journald(tmp_path)["auth_events"]) == 1


def test_symlink_escape_is_contained(tmp_path: Path) -> None:
    """A capture-path symlink pointing outside the root is refused."""
    outside = tmp_path / "outside.json"
    outside.write_text(_accepted(_PUBLIC_IP, "root", 22, 1) + "\n", encoding="utf-8")
    root = tmp_path / "mnt"
    (root / "var/log/journal").mkdir(parents=True)
    (root / "var/log/journal/journalctl.json").symlink_to(outside)

    assert parse_journald(root) == {"auth_events": [], "login_sessions": []}


# --- detector wiring through the parser -----------------------------------


def test_journald_only_bruteforce_fires_one_finding(tmp_path: Path) -> None:
    """A journald-only sshd brute-force fires the auth detector, cited journald."""
    lines = [
        _failed(_PUBLIC_IP, "root", 40000 + i, (i + 1) * 1_000_000) for i in range(6)
    ]
    lines.append(_accepted(_PUBLIC_IP, "root", 41000, 9_000_000))
    _write_journal_json(tmp_path, lines)

    artifacts = collect_linux_artifacts(tmp_path)
    findings = LinuxAuthDetector().analyze(artifacts)

    assert len(findings) == 1
    assert findings[0].artifact_sources == ["journald"]
    assert findings[0].evidence["compromised_user"] == "root"


def test_journald_external_root_login_fires_t1078(tmp_path: Path) -> None:
    """A single journald Accepted for external root fires T1078, cited journald."""
    _write_journal_json(tmp_path, [_accepted(_PUBLIC_IP, "root", 22, 1_000_000)])

    artifacts = collect_linux_artifacts(tmp_path)
    findings = LinuxLoginSessionDetector().analyze(artifacts)

    assert len(findings) == 1
    assert findings[0].artifact_sources == ["journald"]
    assert "journal" in findings[0].description.lower()


# --- the correctness guard: cross-surface dedupe --------------------------


def test_both_surfaces_do_not_double_count_bruteforce(tmp_path: Path) -> None:
    """auth.log + journald logging the SAME attempts must not inflate the count.

    The benign decoy (3 typos then success, below threshold) is present in BOTH
    surfaces at the same wall clock. Without dedupe the merged count would be 6
    and falsely fire; the collector's cross-surface dedupe keeps it at 3 so no
    false positive is raised. (Guard-checked: removing the dedupe reddens this.)
    """
    # auth.log: 3 failed then accepted for a benign user (below threshold 5).
    _write(
        tmp_path / "var/log/auth.log",
        "".join(
            f"May 10 12:00:0{i} host sshd[1]: Failed password for bob "
            f"from {_PUBLIC_IP} port {40000 + i} ssh2\n"
            for i in range(3)
        )
        + f"May 10 12:00:09 host sshd[1]: Accepted password for bob "
        f"from {_PUBLIC_IP} port 41000 ssh2\n",
    )
    # journald: the SAME four events, same wall clock (UTC seconds -> May 10).
    base = 1_746_878_400  # 2025-05-10 12:00:00 UTC -> "May 10 12:00:00"
    lines = [
        _failed(_PUBLIC_IP, "bob", 40000 + i, (base + i) * 1_000_000) for i in range(3)
    ]
    lines.append(_accepted(_PUBLIC_IP, "bob", 41000, (base + 9) * 1_000_000))
    _write_journal_json(tmp_path, lines)

    artifacts = collect_linux_artifacts(tmp_path)

    # Dedupe collapses the duplicated failures: 3, not 6.
    bob_failed = [
        e
        for e in artifacts["auth_events"]
        if e["user"] == "bob" and e["event"] == "failed"
    ]
    assert len(bob_failed) == 3
    assert LinuxAuthDetector().analyze(artifacts) == []


def test_timezone_mismatch_does_not_dedupe_documented_bound(tmp_path: Path) -> None:
    """UTC journald + local-time auth.log fail to dedupe (documented bound).

    Pins the known limitation: the same real event logged to both surfaces at a
    non-UTC-local host carries different wall-clock strings, so it does not
    dedupe. The bounded effect is over-detection (an inflated count), never a
    missed compromise. A future timezone-aware dedupe would flip this assertion
    -- deliberately, not by accident.
    """
    # auth.log at EST (UTC-5): the event's local wall clock is 07:00:00.
    _write(
        tmp_path / "var/log/auth.log",
        f"May 10 07:00:00 host sshd[1]: Failed password for root "
        f"from {_PUBLIC_IP} port 40000 ssh2\n",
    )
    # journald: the SAME instant in UTC (2025-05-10 12:00:00 -> "May 10 12:00:00").
    _write_journal_json(
        tmp_path, [_failed(_PUBLIC_IP, "root", 40000, 1_746_878_400_000_000)]
    )

    failed = [
        e
        for e in collect_linux_artifacts(tmp_path)["auth_events"]
        if e["event"] == "failed"
    ]

    # Not deduped across the timezone gap: two events, not one (over-detection).
    assert len(failed) == 2


def test_split_pair_across_surfaces_stays_chronological(tmp_path: Path) -> None:
    """A pair split across auth.log + journald must not under-count (regression).

    Reality: 6 failures then an Accepted for root. auth.log holds only the first
    failure and the Accepted; journald holds the 5 middle failures at a
    timezone-shifted wall clock so they do NOT exact-dedupe. Appending journald
    after auth.log would place the Accepted before those 5 failures and count 1
    pre-success failure (below threshold) -> missed compromise. The merged
    stream is sorted chronologically, so all 6 failures precede the success and
    the brute-force fires. Guard-checked: dropping the sort reddens this.
    """
    _write(
        tmp_path / "var/log/auth.log",
        f"May 10 12:00:00 host sshd[1]: Failed password for root "
        f"from {_PUBLIC_IP} port 40000 ssh2\n"
        f"May 10 12:00:06 host sshd[1]: Accepted password for root "
        f"from {_PUBLIC_IP} port 41000 ssh2\n",
    )
    # journald: failures at 12:00:01-05 UTC (2025-05-10). base = 12:00:00 UTC.
    base = 1_746_878_400
    _write_journal_json(
        tmp_path,
        [
            _failed(_PUBLIC_IP, "root", 40000 + i, (base + i) * 1_000_000)
            for i in range(1, 6)
        ],
    )

    artifacts = collect_linux_artifacts(tmp_path)
    findings = LinuxAuthDetector().analyze(artifacts)

    assert len(findings) == 1
    assert findings[0].evidence["compromised_user"] == "root"
    # Both surfaces contributed to the pair, so both are cited.
    assert findings[0].artifact_sources == ["auth_log", "journald"]


def test_authlog_only_stream_is_returned_unchanged(tmp_path: Path) -> None:
    """With no journald contribution the auth.log stream keeps its file order.

    Guards the fix's no-regression property: the chronological re-sort runs only
    when journald adds events, so a pure auth.log run is byte-identical to
    before (its rotation-aware, year-aware order is preserved).
    """
    from sift_find_evil.parsers.linux_collector import _merge_auth_events

    # Deliberately non-chronological to prove it is NOT re-sorted.
    authlog = [
        {
            "event": "failed",
            "user": "r",
            "source_ip": "1.2.3.4",
            "port": "2",
            "timestamp": "Dec 31 23:59:59",
        },
        {
            "event": "accepted",
            "user": "r",
            "source_ip": "1.2.3.4",
            "port": "3",
            "timestamp": "Jan 01 00:00:01",
        },
    ]
    assert _merge_auth_events(authlog, []) is authlog


def test_journald_only_events_supplement_authlog(tmp_path: Path) -> None:
    """journald events for a pair auth.log lacks are added (recall)."""
    _write(
        tmp_path / "var/log/auth.log",
        f"May 10 12:00:00 host sshd[1]: Accepted password for alice "
        f"from {_PUBLIC_IP} port 22 ssh2\n",
    )
    # journald carries a DIFFERENT pair auth.log never saw.
    lines = [
        _failed("203.0.113.9", "root", 40000 + i, (i + 1) * 1_000_000) for i in range(6)
    ]
    lines.append(_accepted("203.0.113.9", "root", 41000, 9_000_000))
    _write_journal_json(tmp_path, lines)

    artifacts = collect_linux_artifacts(tmp_path)
    findings = LinuxAuthDetector().analyze(artifacts)

    # The journald-only brute-force is preserved and fires.
    assert len(findings) == 1
    assert findings[0].evidence["compromised_user"] == "root"
    assert findings[0].artifact_sources == ["journald"]
