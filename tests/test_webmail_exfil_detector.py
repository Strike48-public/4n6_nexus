"""Unit tests for WebmailExfilDetector.

Cover:
    - compose without send  -> no finding
    - compose + sent marker -> finding
    - sent marker only      -> finding (sent from another tab counts)
    - sensitive doc access within window -> confidence boost
    - doc access outside window -> no boost
    - PCAP corroboration -> confidence boost
    - multiple sessions cluster -> one finding per session
    - unknown provider handled gracefully
    - timezone naive/aware mismatch does not raise
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from sift_find_evil.detectors.webmail_exfil_detector import (
    MFTAccessRecord,
    WebmailExfilDetector,
)
from sift_find_evil.findings import FindingCategory
from sift_find_evil.parsers.browser_history_parser import BrowserHistoryEntry
from sift_find_evil.parsers.pcap_parser import HTTPRequest


def _history(url: str, ts: datetime) -> BrowserHistoryEntry:
    return BrowserHistoryEntry(
        timestamp=ts,
        url=url,
        title=None,
        visit_count=1,
        browser="chrome",
        profile="Default",
    )


def test_compose_without_send_returns_nothing() -> None:
    detector = WebmailExfilDetector()
    entries = [
        _history(
            "https://mail.google.com/mail/u/0/#compose",
            datetime(2025, 3, 15, 10, 25, tzinfo=timezone.utc),
        ),
    ]
    assert detector.analyze(browser_history=entries) == []


def test_compose_then_sent_marker_emits_finding() -> None:
    detector = WebmailExfilDetector()
    entries = [
        _history(
            "https://mail.google.com/mail/u/0/#compose",
            datetime(2025, 3, 15, 10, 25, 10, tzinfo=timezone.utc),
        ),
        _history(
            "https://mail.google.com/mail/u/0/#sent",
            datetime(2025, 3, 15, 10, 30, 0, tzinfo=timezone.utc),
        ),
    ]
    findings = detector.analyze(browser_history=entries)
    assert len(findings) == 1
    assert findings[0].category == FindingCategory.DATA_EXFILTRATION
    assert "Gmail" in findings[0].title
    assert findings[0].confidence == pytest.approx(0.55)
    # Structured discriminator so scoring doesn't depend on title substrings.
    assert findings[0].evidence["exfil_type"] == "webmail"


def test_sensitive_doc_access_within_window_boosts_confidence() -> None:
    detector = WebmailExfilDetector(window_minutes=10)
    send_ts = datetime(2025, 3, 15, 10, 30, 0, tzinfo=timezone.utc)
    entries = [
        _history("https://mail.google.com/mail/u/0/#compose", send_ts - timedelta(minutes=5)),
        _history("https://mail.google.com/mail/u/0/#sent", send_ts),
    ]
    mft = [
        MFTAccessRecord(
            filename="patents_summary.docx",
            parent_path=r"C:\Users\insider\Documents",
            accessed=send_ts - timedelta(minutes=6),
        ),
    ]
    findings = detector.analyze(browser_history=entries, mft_records=mft)
    assert len(findings) == 1
    assert findings[0].confidence == pytest.approx(0.80)
    assert "patents_summary.docx" in findings[0].description


def test_doc_access_outside_window_does_not_boost() -> None:
    detector = WebmailExfilDetector(window_minutes=10)
    send_ts = datetime(2025, 3, 15, 10, 30, tzinfo=timezone.utc)
    entries = [
        _history("https://mail.google.com/mail/u/0/#compose", send_ts - timedelta(minutes=5)),
        _history("https://mail.google.com/mail/u/0/#sent", send_ts),
    ]
    mft = [
        MFTAccessRecord(
            filename="patents_summary.docx",
            parent_path=r"C:\Users\insider\Documents",
            accessed=send_ts - timedelta(hours=2),  # way outside window
        ),
    ]
    findings = detector.analyze(browser_history=entries, mft_records=mft)
    assert len(findings) == 1
    assert findings[0].confidence == pytest.approx(0.55)


def test_non_sensitive_doc_access_does_not_boost() -> None:
    detector = WebmailExfilDetector(window_minutes=10)
    send_ts = datetime(2025, 3, 15, 10, 30, tzinfo=timezone.utc)
    entries = [
        _history("https://mail.google.com/mail/u/0/#sent", send_ts),
    ]
    mft = [
        MFTAccessRecord(
            filename="readme.txt",
            parent_path=r"C:\Users\insider\Documents",
            accessed=send_ts - timedelta(minutes=1),
        ),
    ]
    findings = detector.analyze(browser_history=entries, mft_records=mft)
    assert len(findings) == 1
    assert findings[0].confidence == pytest.approx(0.55)


def test_pcap_corroboration_boosts_confidence() -> None:
    detector = WebmailExfilDetector(window_minutes=10)
    send_ts = datetime(2025, 3, 15, 10, 30, tzinfo=timezone.utc)
    entries = [_history("https://mail.google.com/mail/u/0/#sent", send_ts)]
    http = [
        HTTPRequest(
            frame_number=1,
            timestamp=send_ts - timedelta(minutes=1),
            src_ip="10.0.0.5",
            dst_ip="142.250.80.100",
            method="POST",
            host="mail.google.com",
            uri="/mail/u/0/?ui=2&ik=...",
        ),
    ]
    findings = detector.analyze(browser_history=entries, http_requests=http)
    assert len(findings) == 1
    assert findings[0].confidence == pytest.approx(0.70)


def test_all_signals_caps_at_ceiling() -> None:
    detector = WebmailExfilDetector(window_minutes=10)
    send_ts = datetime(2025, 3, 15, 10, 30, tzinfo=timezone.utc)
    entries = [_history("https://mail.google.com/mail/u/0/#sent", send_ts)]
    mft = [
        MFTAccessRecord(
            filename="patents_summary.docx",
            parent_path=r"C:\Users\insider\Documents",
            accessed=send_ts - timedelta(minutes=1),
        ),
    ]
    http = [
        HTTPRequest(
            frame_number=1,
            timestamp=send_ts,
            src_ip="10.0.0.5",
            dst_ip="142.250.80.100",
            method="POST",
            host="mail.google.com",
            uri="/send",
        ),
    ]
    findings = detector.analyze(
        browser_history=entries,
        mft_records=mft,
        http_requests=http,
    )
    assert len(findings) == 1
    # 0.55 + 0.25 + 0.15 = 0.95 exactly, no cap needed but cap still respected.
    assert findings[0].confidence == pytest.approx(0.95)
    assert findings[0].confidence_label == "Very High"


def test_pcap_alone_without_send_marker_still_emits() -> None:
    """PCAP POST to mail.google.com around compose alone is enough corroboration."""
    detector = WebmailExfilDetector(window_minutes=10)
    compose_ts = datetime(2025, 3, 15, 10, 25, tzinfo=timezone.utc)
    entries = [_history("https://mail.google.com/mail/u/0/#compose", compose_ts)]
    http = [
        HTTPRequest(
            frame_number=1,
            timestamp=compose_ts + timedelta(minutes=2),
            src_ip="10.0.0.5",
            dst_ip="142.250.80.100",
            method="POST",
            host="mail.google.com",
            uri="/send",
        ),
    ]
    findings = detector.analyze(browser_history=entries, http_requests=http)
    assert len(findings) == 1


def test_multiple_sessions_emit_multiple_findings() -> None:
    detector = WebmailExfilDetector()
    day1 = datetime(2025, 3, 15, 10, 30, tzinfo=timezone.utc)
    day2 = day1 + timedelta(hours=5)
    entries = [
        _history("https://mail.google.com/mail/u/0/#sent", day1),
        _history("https://mail.google.com/mail/u/0/#sent", day2),
    ]
    findings = detector.analyze(browser_history=entries)
    assert len(findings) == 2


def test_empty_inputs_return_empty() -> None:
    detector = WebmailExfilDetector()
    assert detector.analyze(browser_history=[]) == []


def test_non_webmail_urls_ignored() -> None:
    detector = WebmailExfilDetector()
    entries = [
        _history(
            "https://example.com/login#compose",
            datetime(2025, 3, 15, 10, 25, tzinfo=timezone.utc),
        ),
    ]
    assert detector.analyze(browser_history=entries) == []


def test_naive_and_aware_timestamps_do_not_raise() -> None:
    detector = WebmailExfilDetector()
    send_ts = datetime(2025, 3, 15, 10, 30, tzinfo=timezone.utc)
    entries = [_history("https://mail.google.com/mail/u/0/#sent", send_ts)]
    mft = [
        MFTAccessRecord(
            filename="patents_summary.docx",
            parent_path=r"C:\Users\insider\Documents",
            accessed=datetime(2025, 3, 15, 10, 29),  # naive — should still compare
        ),
    ]
    findings = detector.analyze(browser_history=entries, mft_records=mft)
    assert len(findings) == 1


def test_invalid_window_raises() -> None:
    with pytest.raises(ValueError):
        WebmailExfilDetector(window_minutes=0)
