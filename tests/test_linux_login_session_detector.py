"""Tests for the Linux login-session detector (SFE-fjla).

Exercises the valid-account-abuse signal recovered from wtmp/utmp login
sessions: an interactive privileged (root) login from an external address fires
(T1078), while local/console logins, private-IP logins, and non-privileged
users do not. Also covers the RFC-5737 external-classification caveat and the
dedupe against the auth.log brute-force finding. Inputs are synthetic in-memory
dicts.
"""

from __future__ import annotations

from sift_find_evil.detectors.linux_wtmp import LinuxLoginSessionDetector
from sift_find_evil.findings import FindingCategory


def _session(user: str, source_ip: str, line: str = "pts/0") -> dict:
    return {
        "user": user,
        "line": line,
        "host": "",
        "source_ip": source_ip,
        "timestamp": 1710000000,
        "source_path": "/var/log/wtmp",
    }


def test_privileged_external_login_is_flagged() -> None:
    """A root login from a public IP fires a T1078 credential-access finding."""
    findings = LinuxLoginSessionDetector().analyze(
        {"login_sessions": [_session("root", "45.83.122.10")]}
    )

    assert len(findings) == 1
    f = findings[0]
    assert f.category is FindingCategory.CREDENTIAL_ACCESS
    assert f.evidence["mitre_technique"] == "T1078"
    assert f.evidence["source_ip"] == "45.83.122.10"
    assert f.evidence["account"] == "root"
    assert f.artifact_sources == ["wtmp"]


def test_local_console_root_login_does_not_fire() -> None:
    """A root login with no source address (console/tty) is in-perimeter."""
    findings = LinuxLoginSessionDetector().analyze(
        {"login_sessions": [_session("root", "", line="tty1")]}
    )

    assert findings == []


def test_private_ip_root_login_does_not_fire() -> None:
    """A root login from an RFC1918 private IP is not external."""
    findings = LinuxLoginSessionDetector().analyze(
        {"login_sessions": [_session("root", "10.10.0.5")]}
    )

    assert findings == []


def test_non_privileged_external_login_does_not_fire() -> None:
    """A normal-user login from a public IP is routine, not flagged."""
    findings = LinuxLoginSessionDetector().analyze(
        {"login_sessions": [_session("analyst", "45.83.122.10")]}
    )

    assert findings == []


def test_rfc5737_doc_range_is_not_external() -> None:
    """RFC-5737 documentation ranges classify as non-global, so must not fire.

    Guards the vacuous-pass trap: a fixture that plants a doc-range IP
    (203.0.113/198.51.100/192.0.2) would silently never fire.
    """
    docs = ["203.0.113.5", "198.51.100.7", "192.0.2.9"]
    entries = [_session("root", ip) for ip in docs]

    assert LinuxLoginSessionDetector().analyze({"login_sessions": entries}) == []


def test_repeated_sessions_dedupe_to_one_finding() -> None:
    """Multiple sessions for the same (ip, user) yield a single finding."""
    entries = [
        _session("root", "45.83.122.10", line="pts/1"),
        _session("root", "45.83.122.10", line="pts/2"),
    ]

    assert len(LinuxLoginSessionDetector().analyze({"login_sessions": entries})) == 1


def test_pair_owned_by_auth_brute_force_is_suppressed() -> None:
    """A (ip, user) the auth surface owns as a brute-force compromise is deduped.

    The wtmp session for a pair that auth.log already reports (>=5 failures then
    a success) must not be double-counted under CREDENTIAL_ACCESS.
    """
    auth_events = [
        {"event": "failed", "user": "root", "source_ip": "45.83.122.10"}
    ] * 5 + [{"event": "accepted", "user": "root", "source_ip": "45.83.122.10"}]

    findings = LinuxLoginSessionDetector().analyze(
        {
            "login_sessions": [_session("root", "45.83.122.10")],
            "auth_events": auth_events,
        }
    )

    assert findings == []


def test_login_not_owned_by_auth_still_fires() -> None:
    """A below-threshold auth trail does not suppress the login-session finding.

    Only a genuine brute-force compromise (>=5 pre-success failures) suppresses;
    a couple of failures must not, or the T1078 signal would be lost.
    """
    auth_events = [
        {"event": "failed", "user": "root", "source_ip": "45.83.122.10"},
        {"event": "accepted", "user": "root", "source_ip": "45.83.122.10"},
    ]

    findings = LinuxLoginSessionDetector().analyze(
        {
            "login_sessions": [_session("root", "45.83.122.10")],
            "auth_events": auth_events,
        }
    )

    assert len(findings) == 1


def test_empty_input_returns_no_findings() -> None:
    """Missing/empty login_sessions yields an empty list, not an error."""
    assert LinuxLoginSessionDetector().analyze({}) == []
    assert LinuxLoginSessionDetector().analyze({"login_sessions": []}) == []
