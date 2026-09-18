"""Tests for the Linux authentication detector (SFE-rfhz).

Exercises the SSH brute-force / valid-accounts compromise signal: a source IP
with at least the failed-attempt threshold of ``Failed password`` events that
is *followed* by an ``Accepted`` event for the same IP (T1110.001 brute force +
T1078 valid accounts). The malicious case, three precision controls (a benign
low-failure login, a failed-only flood with no success, and a clean login), and
the empty-input case are all covered so precision is exercised, not assumed.

API under test: ``LinuxAuthDetector.analyze(artifacts: dict) -> list[Finding]``
reading ``artifacts["auth_events"]``. Inputs are synthetic in-memory dicts.
"""

from __future__ import annotations

from sift_find_evil.detectors.linux_auth import LinuxAuthDetector
from sift_find_evil.findings import FindingCategory


def _failed(ip: str, user: str = "root") -> dict:
    return {"event": "failed", "user": user, "source_ip": ip, "raw": "Failed"}


def _accepted(ip: str, user: str = "root") -> dict:
    return {"event": "accepted", "user": user, "source_ip": ip, "raw": "Accepted"}


def test_brute_force_success_is_flagged() -> None:
    """>= threshold failures then an accepted login for the same IP fires."""
    events = [_failed("203.0.113.5") for _ in range(8)]
    events.append(_accepted("203.0.113.5"))

    findings = LinuxAuthDetector().analyze({"auth_events": events})

    assert len(findings) == 1
    finding = findings[0]
    assert finding.category is FindingCategory.CREDENTIAL_ACCESS
    assert finding.severity == "critical"
    assert finding.evidence["source_ip"] == "203.0.113.5"
    assert finding.evidence["mitre_technique"] == "T1110.001"
    assert finding.artifact_sources == ["auth_log"]


def test_accepted_before_failures_is_not_a_compromise() -> None:
    """A success followed by later typos is not brute force (temporal guard)."""
    events = [_accepted("203.0.113.5")] + [_failed("203.0.113.5") for _ in range(8)]

    assert LinuxAuthDetector().analyze({"auth_events": events}) == []


def test_failures_and_success_for_different_users_do_not_fire() -> None:
    """One user's typos + a different user's login from a shared IP is benign.

    Guards the NAT / shared-egress false positive: grouping is per (ip, user).
    """
    events = [_failed("10.0.0.100", "alice") for _ in range(8)]
    events.append(_accepted("10.0.0.100", "bob"))

    assert LinuxAuthDetector().analyze({"auth_events": events}) == []


def test_low_failure_count_with_success_is_benign() -> None:
    """A couple of typos then a login (below threshold) is not flagged."""
    events = [_failed("10.0.0.7", "alice"), _failed("10.0.0.7", "alice")]
    events.append(_accepted("10.0.0.7", "alice"))

    assert LinuxAuthDetector().analyze({"auth_events": events}) == []


def test_failed_flood_without_success_is_not_a_compromise() -> None:
    """A brute-force attempt with no accepted login is not a success finding."""
    events = [_failed("198.51.100.9") for _ in range(20)]

    assert LinuxAuthDetector().analyze({"auth_events": events}) == []


def test_clean_single_login_is_benign() -> None:
    """One successful login with zero failures produces no finding."""
    assert LinuxAuthDetector().analyze({"auth_events": [_accepted("10.0.0.5")]}) == []


def test_events_without_source_ip_are_skipped() -> None:
    """Malformed events lacking a source IP are ignored, not counted."""
    events = [{"event": "failed", "user": "root"} for _ in range(8)]
    events.append({"event": "accepted", "user": "root"})

    assert LinuxAuthDetector().analyze({"auth_events": events}) == []


def test_empty_input_returns_no_findings() -> None:
    """Missing/empty auth_events yields an empty list, not an error."""
    assert LinuxAuthDetector().analyze({}) == []
    assert LinuxAuthDetector().analyze({"auth_events": []}) == []
