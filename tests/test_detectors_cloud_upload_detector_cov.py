"""Coverage-focused tests for CloudUploadDetector.

Targets the uncovered branches:
    - line 296: provider fallthrough -> "unknown cloud-storage provider"
      (upload URL matches _CLOUD_URL_SUBSTRINGS but no provider name matches,
       e.g. filebin.net / send-anywhere.com).
    - line 329: HTTP request with a non-POST/PUT method is skipped.
    - line 332: HTTP request to a non-cloud host is skipped.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from sift_find_evil.detectors.cloud_upload_detector import CloudUploadDetector
from sift_find_evil.detectors.webmail_exfil_detector import MFTAccessRecord
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


def _http(method: str, host: str, ts: datetime) -> HTTPRequest:
    return HTTPRequest(
        frame_number=1,
        timestamp=ts,
        src_ip="10.0.0.5",
        dst_ip="93.184.216.34",
        method=method,
        host=host,
        uri="/upload",
    )


def test_filebin_url_yields_unknown_provider() -> None:
    """filebin.net is an upload surface but has no friendly provider name.

    Drives the _identify_provider fallthrough (line 296).
    """
    detector = CloudUploadDetector()
    entries = [
        _history(
            "https://filebin.net/abc123",
            datetime(2025, 3, 15, 10, 30, tzinfo=timezone.utc),
        ),
    ]
    findings = detector.analyze(browser_history=entries)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.category == FindingCategory.DATA_EXFILTRATION
    assert finding.evidence["provider"] == "unknown cloud-storage provider"
    assert "unknown cloud-storage provider" in finding.title


def test_send_anywhere_url_yields_unknown_provider() -> None:
    """send-anywhere.com is also an upload surface with no provider name."""
    detector = CloudUploadDetector()
    entries = [
        _history(
            "https://send-anywhere.com/",
            datetime(2025, 3, 15, 10, 30, tzinfo=timezone.utc),
        ),
    ]
    findings = detector.analyze(browser_history=entries)
    assert len(findings) == 1
    assert findings[0].evidence["provider"] == "unknown cloud-storage provider"


def test_non_post_put_method_is_skipped() -> None:
    """A GET to a cloud host must not count as corroboration (line 329).

    A bare GET in the window should leave confidence at the 0.55 base.
    """
    detector = CloudUploadDetector(window_minutes=10)
    upload_ts = datetime(2025, 3, 15, 10, 30, tzinfo=timezone.utc)
    entries = [_history("https://www.dropbox.com/upload", upload_ts)]
    http = [
        _http("GET", "content.dropboxapi.com", upload_ts + timedelta(minutes=1)),
    ]
    findings = detector.analyze(browser_history=entries, http_requests=http)
    assert len(findings) == 1
    assert findings[0].confidence == pytest.approx(0.55)
    assert findings[0].evidence["http_corroboration_count"] == 0


def test_post_to_non_cloud_host_is_skipped() -> None:
    """A POST to a non-cloud host must not count as corroboration (line 332)."""
    detector = CloudUploadDetector(window_minutes=10)
    upload_ts = datetime(2025, 3, 15, 10, 30, tzinfo=timezone.utc)
    entries = [_history("https://www.dropbox.com/upload", upload_ts)]
    http = [
        _http("POST", "analytics.example.com", upload_ts + timedelta(minutes=1)),
    ]
    findings = detector.analyze(browser_history=entries, http_requests=http)
    assert len(findings) == 1
    assert findings[0].confidence == pytest.approx(0.55)
    assert findings[0].evidence["http_corroboration_count"] == 0


def test_non_sensitive_mft_record_is_skipped() -> None:
    """A non-sensitive filename in the window must not boost confidence.

    Drives the `continue` skip for non-sensitive extensions in
    _find_sensitive_document_accesses.
    """
    detector = CloudUploadDetector(window_minutes=10)
    upload_ts = datetime(2025, 3, 15, 10, 30, tzinfo=timezone.utc)
    entries = [_history("https://www.dropbox.com/upload", upload_ts)]
    mft = [
        MFTAccessRecord(
            filename="notes.txt",  # .txt not in sensitive extensions
            parent_path=r"C:\Users\insider\Documents",
            accessed=upload_ts,
        ),
    ]
    findings = detector.analyze(browser_history=entries, mft_records=mft)
    assert len(findings) == 1
    assert findings[0].confidence == pytest.approx(0.55)
    assert findings[0].evidence["sensitive_documents"] == []


def test_mixed_http_only_cloud_post_corroborates() -> None:
    """Mix of skipped (GET + non-cloud POST) and one valid cloud POST.

    Drives lines 329, 332 (skips) AND the positive corroboration path in one run.
    """
    detector = CloudUploadDetector(window_minutes=10)
    upload_ts = datetime(2025, 3, 15, 10, 30, tzinfo=timezone.utc)
    entries = [_history("https://www.dropbox.com/upload", upload_ts)]
    http = [
        _http("GET", "content.dropboxapi.com", upload_ts),  # skipped: not POST/PUT
        _http("POST", "analytics.example.com", upload_ts),  # skipped: non-cloud host
        _http("PUT", "content.dropboxapi.com", upload_ts),  # counts
    ]
    findings = detector.analyze(browser_history=entries, http_requests=http)
    assert len(findings) == 1
    assert findings[0].confidence == pytest.approx(0.70)
    assert findings[0].evidence["http_corroboration_count"] == 1
