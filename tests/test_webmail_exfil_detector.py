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
        _history(
            "https://mail.google.com/mail/u/0/#compose", send_ts - timedelta(minutes=5)
        ),
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
        _history(
            "https://mail.google.com/mail/u/0/#compose", send_ts - timedelta(minutes=5)
        ),
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


def test_outlook_provider_detection() -> None:
    """Test Outlook provider detection."""
    detector = WebmailExfilDetector()
    entries = [
        _history(
            "https://outlook.live.com/mail/0/#compose",
            datetime(2025, 3, 15, 10, 30, tzinfo=timezone.utc),
        ),
        _history(
            "https://outlook.office.com/mail/0/#sent",
            datetime(2025, 3, 15, 10, 31, tzinfo=timezone.utc),
        ),
    ]
    findings = detector.analyze(browser_history=entries)
    assert len(findings) == 1
    assert "Outlook" in findings[0].evidence["provider"]


def test_yahoo_provider_detection() -> None:
    """Test Yahoo Mail provider detection."""
    detector = WebmailExfilDetector()
    entries = [
        _history(
            "https://mail.yahoo.com/d/#compose",
            datetime(2025, 3, 15, 10, 30, tzinfo=timezone.utc),
        ),
        _history(
            "https://mail.yahoo.com/d/#sent",
            datetime(2025, 3, 15, 10, 31, tzinfo=timezone.utc),
        ),
    ]
    findings = detector.analyze(browser_history=entries)
    assert len(findings) == 1
    assert "Yahoo" in findings[0].evidence["provider"]


def test_protonmail_provider_detection() -> None:
    """Test ProtonMail provider detection."""
    detector = WebmailExfilDetector()
    entries = [
        _history(
            "https://mail.proton.me/u/0/#compose",
            datetime(2025, 3, 15, 10, 30, tzinfo=timezone.utc),
        ),
        _history(
            "https://mail.proton.me/u/0/#sent",
            datetime(2025, 3, 15, 10, 31, tzinfo=timezone.utc),
        ),
    ]
    findings = detector.analyze(browser_history=entries)
    assert len(findings) == 1
    assert "ProtonMail" in findings[0].evidence["provider"]


def test_tutanota_provider_detection() -> None:
    """Test Tutanota provider detection."""
    detector = WebmailExfilDetector()
    entries = [
        _history(
            "https://mail.tutanota.com/mail/#compose",
            datetime(2025, 3, 15, 10, 30, tzinfo=timezone.utc),
        ),
        _history(
            "https://mail.tutanota.com/mail/#sent",
            datetime(2025, 3, 15, 10, 31, tzinfo=timezone.utc),
        ),
    ]
    findings = detector.analyze(browser_history=entries)
    assert len(findings) == 1
    assert "Tutanota" in findings[0].evidence["provider"]


def test_http_corroboration_requires_post_or_connect() -> None:
    """Test HTTP corroboration only counts POST/CONNECT methods."""
    detector = WebmailExfilDetector(window_minutes=10)
    send_ts = datetime(2025, 3, 15, 10, 30, tzinfo=timezone.utc)
    entries = [_history("https://mail.google.com/mail/u/0/#sent", send_ts)]

    # GET request should not trigger corroboration
    http_get = [
        HTTPRequest(
            frame_number=1,
            timestamp=send_ts,
            src_ip="192.168.1.100",
            dst_ip="172.217.16.165",
            method="GET",
            host="mail.google.com",
            uri="/mail/u/0/",
            user_agent="Mozilla/5.0",
        ),
    ]
    findings_no_corroboration = detector.analyze(
        browser_history=entries, http_requests=http_get
    )
    assert len(findings_no_corroboration) == 1
    # Base confidence without corroboration
    base_confidence = findings_no_corroboration[0].confidence

    # POST request should trigger corroboration
    http_post = [
        HTTPRequest(
            frame_number=1,
            timestamp=send_ts,
            src_ip="192.168.1.100",
            dst_ip="172.217.16.165",
            method="POST",
            host="mail.google.com",
            uri="/mail/u/0/",
            user_agent="Mozilla/5.0",
        ),
    ]
    findings_with_corroboration = detector.analyze(
        browser_history=entries, http_requests=http_post
    )
    assert len(findings_with_corroboration) == 1
    assert findings_with_corroboration[0].confidence > base_confidence


def test_http_corroboration_filters_non_webmail_hosts() -> None:
    """Test HTTP corroboration filters out non-webmail hosts."""
    detector = WebmailExfilDetector(window_minutes=10)
    send_ts = datetime(2025, 3, 15, 10, 30, tzinfo=timezone.utc)
    entries = [_history("https://mail.google.com/mail/u/0/#sent", send_ts)]

    # POST to non-webmail host should not boost confidence
    http_non_webmail = [
        HTTPRequest(
            frame_number=1,
            timestamp=send_ts,
            src_ip="192.168.1.100",
            dst_ip="93.184.216.34",
            method="POST",
            host="example.com",
            uri="/api/upload",
            user_agent="Mozilla/5.0",
        ),
    ]
    findings = detector.analyze(browser_history=entries, http_requests=http_non_webmail)
    assert len(findings) == 1
    # Should not have HTTP corroboration boost
    assert "http_corroboration_count" not in findings[0].evidence or findings[0].evidence["http_corroboration_count"] == 0


def test_unknown_webmail_provider_detection() -> None:
    """Test detection returns 'unknown webmail provider' for unrecognized domains."""
    detector = WebmailExfilDetector()
    entries = [
        _history(
            "https://mail.example.com/#compose",
            datetime(2025, 3, 15, 10, 30, tzinfo=timezone.utc),
        ),
        _history(
            "https://mail.example.com/#sent",
            datetime(2025, 3, 15, 10, 31, tzinfo=timezone.utc),
        ),
    ]
    findings = detector.analyze(browser_history=entries)
    assert len(findings) == 1
    assert findings[0].evidence["provider"] == "unknown webmail provider"
