"""Unit tests for CloudUploadDetector.

Cover:
    - visit to cloud upload URL alone -> finding
    - non-cloud URL -> no finding
    - sensitive doc access within window -> confidence boost
    - doc access outside window -> no boost
    - PCAP POST corroboration -> confidence boost
    - multiple upload sessions cluster -> one finding per session
    - provider identification (Dropbox, Google Drive, OneDrive, Mega, Box, WeTransfer)
    - timezone naive/aware mismatch does not raise
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


def test_dropbox_upload_url_emits_finding() -> None:
    detector = CloudUploadDetector()
    entries = [
        _history(
            "https://www.dropbox.com/home/Uploads",
            datetime(2025, 3, 15, 10, 30, tzinfo=timezone.utc),
        ),
        _history(
            "https://www.dropbox.com/upload",
            datetime(2025, 3, 15, 10, 30, 10, tzinfo=timezone.utc),
        ),
    ]
    findings = detector.analyze(browser_history=entries)
    assert len(findings) == 1
    assert findings[0].category == FindingCategory.DATA_EXFILTRATION
    assert "Dropbox" in findings[0].title
    assert findings[0].confidence == pytest.approx(0.55)
    # Structured discriminator so scoring doesn't depend on title substrings.
    assert findings[0].evidence["exfil_type"] == "cloud_upload"


def test_google_drive_upload_detected() -> None:
    detector = CloudUploadDetector()
    entries = [
        _history(
            "https://drive.google.com/drive/u/0/my-drive",
            datetime(2025, 3, 15, 10, 30, tzinfo=timezone.utc),
        ),
        _history(
            "https://drive.google.com/drive/u/0/folders/upload",
            datetime(2025, 3, 15, 10, 30, 10, tzinfo=timezone.utc),
        ),
    ]
    findings = detector.analyze(browser_history=entries)
    assert len(findings) == 1
    assert "Google Drive" in findings[0].title


def test_onedrive_upload_detected() -> None:
    detector = CloudUploadDetector()
    entries = [
        _history(
            "https://onedrive.live.com/?id=root&cid=ABC",
            datetime(2025, 3, 15, 10, 30, tzinfo=timezone.utc),
        ),
    ]
    findings = detector.analyze(browser_history=entries)
    assert len(findings) == 1
    assert "OneDrive" in findings[0].title


def test_mega_upload_detected() -> None:
    detector = CloudUploadDetector()
    entries = [
        _history(
            "https://mega.nz/fm/abcd1234",
            datetime(2025, 3, 15, 10, 30, tzinfo=timezone.utc),
        ),
    ]
    findings = detector.analyze(browser_history=entries)
    assert len(findings) == 1
    assert "Mega" in findings[0].title


def test_wetransfer_upload_detected() -> None:
    detector = CloudUploadDetector()
    entries = [
        _history(
            "https://wetransfer.com/",
            datetime(2025, 3, 15, 10, 30, tzinfo=timezone.utc),
        ),
    ]
    findings = detector.analyze(browser_history=entries)
    assert len(findings) == 1
    assert "WeTransfer" in findings[0].title


def test_box_upload_detected() -> None:
    detector = CloudUploadDetector()
    entries = [
        _history(
            "https://app.box.com/folder/12345",
            datetime(2025, 3, 15, 10, 30, tzinfo=timezone.utc),
        ),
    ]
    findings = detector.analyze(browser_history=entries)
    assert len(findings) == 1
    assert "Box" in findings[0].title


def test_non_cloud_url_ignored() -> None:
    detector = CloudUploadDetector()
    entries = [
        _history(
            "https://example.com/upload",
            datetime(2025, 3, 15, 10, 30, tzinfo=timezone.utc),
        ),
    ]
    assert detector.analyze(browser_history=entries) == []


def test_sensitive_doc_access_within_window_boosts_confidence() -> None:
    detector = CloudUploadDetector(window_minutes=10)
    upload_ts = datetime(2025, 3, 15, 10, 30, tzinfo=timezone.utc)
    entries = [
        _history("https://www.dropbox.com/upload", upload_ts),
    ]
    mft = [
        MFTAccessRecord(
            filename="customer_list.xlsx",
            parent_path=r"C:\Users\insider\Documents",
            accessed=upload_ts - timedelta(minutes=3),
        ),
    ]
    findings = detector.analyze(browser_history=entries, mft_records=mft)
    assert len(findings) == 1
    assert findings[0].confidence == pytest.approx(0.80)
    assert "customer_list.xlsx" in findings[0].description


def test_doc_access_outside_window_does_not_boost() -> None:
    detector = CloudUploadDetector(window_minutes=10)
    upload_ts = datetime(2025, 3, 15, 10, 30, tzinfo=timezone.utc)
    entries = [_history("https://www.dropbox.com/upload", upload_ts)]
    mft = [
        MFTAccessRecord(
            filename="customer_list.xlsx",
            parent_path=r"C:\Users\insider\Documents",
            accessed=upload_ts - timedelta(hours=2),
        ),
    ]
    findings = detector.analyze(browser_history=entries, mft_records=mft)
    assert len(findings) == 1
    assert findings[0].confidence == pytest.approx(0.55)


def test_pcap_corroboration_boosts_confidence() -> None:
    detector = CloudUploadDetector(window_minutes=10)
    upload_ts = datetime(2025, 3, 15, 10, 30, tzinfo=timezone.utc)
    entries = [_history("https://www.dropbox.com/upload", upload_ts)]
    http = [
        HTTPRequest(
            frame_number=1,
            timestamp=upload_ts + timedelta(minutes=1),
            src_ip="10.0.0.5",
            dst_ip="162.125.1.1",
            method="POST",
            host="content.dropboxapi.com",
            uri="/2/files/upload",
        ),
    ]
    findings = detector.analyze(browser_history=entries, http_requests=http)
    assert len(findings) == 1
    assert findings[0].confidence == pytest.approx(0.70)


def test_all_signals_caps_at_ceiling() -> None:
    detector = CloudUploadDetector(window_minutes=10)
    upload_ts = datetime(2025, 3, 15, 10, 30, tzinfo=timezone.utc)
    entries = [_history("https://www.dropbox.com/upload", upload_ts)]
    mft = [
        MFTAccessRecord(
            filename="customer_list.xlsx",
            parent_path=r"C:\Users\insider\Documents",
            accessed=upload_ts - timedelta(minutes=2),
        ),
    ]
    http = [
        HTTPRequest(
            frame_number=1,
            timestamp=upload_ts,
            src_ip="10.0.0.5",
            dst_ip="162.125.1.1",
            method="POST",
            host="content.dropboxapi.com",
            uri="/2/files/upload",
        ),
    ]
    findings = detector.analyze(
        browser_history=entries,
        mft_records=mft,
        http_requests=http,
    )
    assert len(findings) == 1
    assert findings[0].confidence == pytest.approx(0.95)
    assert findings[0].confidence_label == "Very High"


def test_multiple_sessions_emit_multiple_findings() -> None:
    detector = CloudUploadDetector()
    session1 = datetime(2025, 3, 15, 10, 30, tzinfo=timezone.utc)
    session2 = session1 + timedelta(hours=5)
    entries = [
        _history("https://www.dropbox.com/upload", session1),
        _history("https://www.dropbox.com/upload", session2),
    ]
    findings = detector.analyze(browser_history=entries)
    assert len(findings) == 2


def test_empty_inputs_return_empty() -> None:
    detector = CloudUploadDetector()
    assert detector.analyze(browser_history=[]) == []


def test_naive_and_aware_timestamps_do_not_raise() -> None:
    detector = CloudUploadDetector()
    upload_ts = datetime(2025, 3, 15, 10, 30, tzinfo=timezone.utc)
    entries = [_history("https://www.dropbox.com/upload", upload_ts)]
    mft = [
        MFTAccessRecord(
            filename="customer_list.xlsx",
            parent_path=r"C:\Users\insider\Documents",
            accessed=datetime(2025, 3, 15, 10, 29),  # naive
        ),
    ]
    findings = detector.analyze(browser_history=entries, mft_records=mft)
    assert len(findings) == 1


def test_invalid_window_raises() -> None:
    with pytest.raises(ValueError):
        CloudUploadDetector(window_minutes=0)
