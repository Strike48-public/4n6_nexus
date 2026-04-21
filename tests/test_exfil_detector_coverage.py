"""Comprehensive tests for exfil_detector.py to achieve 80%+ coverage.

This test file focuses on the missing lines identified in coverage report:
- Lines 73, 114, 142-147, 169-197, 215-258, 263-301, 306, 337-398
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock


from sift_find_evil.disk.exfil_detector import (
    ExfilMatch,
    ExfilFinding,
    _compute_file_hash,
    _filter_mft_by_email_timeframe,
    _correlate_hashes,
    _build_reasoning,
    _build_evidence,
    detect_exfiltration,
)
from sift_find_evil.findings.categories import FindingCategory
from sift_find_evil.parsers.mft_parser import MFTEntry
from sift_find_evil.parsers.pst_parser import EmailMessage, Attachment


# Helper functions to create test data


def create_test_mft_entry(
    file_path: str = "C:\\test.doc",
    file_size: int = 1024,
    fn_modified: datetime | None = None,
    si_modified: datetime | None = None,
) -> MFTEntry:
    """Create a test MFT entry with minimal required fields."""
    return MFTEntry(
        entry_number=100,
        file_name=Path(file_path).name,
        parent_path=str(Path(file_path).parent),
        file_path=file_path,
        file_size=file_size,
        is_directory=False,
        in_use=True,
        si_created=si_modified or datetime(2009, 12, 11, 16, 0, 0, tzinfo=timezone.utc),
        si_modified=si_modified,
        si_accessed=None,
        si_mft_modified=None,
        fn_created=fn_modified or datetime(2009, 12, 11, 16, 0, 0, tzinfo=timezone.utc),
        fn_modified=fn_modified,
        fn_accessed=None,
        fn_mft_modified=None,
    )


def create_test_attachment(
    name: str = "test.doc",
    size: int = 1024,
    sha256: str = "abc123",
) -> Attachment:
    """Create a test email attachment."""
    return Attachment(name=name, size=size, sha256=sha256)


def create_test_email(
    subject: str = "Test Subject",
    submit_time: datetime | None = None,
    delivery_time: datetime | None = None,
    sender_email: str = "sender@test.com",
    attachments: list[Attachment] | None = None,
) -> EmailMessage:
    """Create a test email message."""
    return EmailMessage(
        folder="Sent Items",
        submit_time=submit_time,
        delivery_time=delivery_time,
        sender_name="Test Sender",
        sender_email=sender_email,
        subject=subject,
        transport_headers="",
        body_preview="Test body",
        attachments=tuple(attachments or []),
    )


# Tests for ExfilMatch.to_dict()


def test_exfil_match_to_dict_with_all_fields():
    """Test ExfilMatch.to_dict() serializes all fields correctly."""
    match = ExfilMatch(
        file_path="C:\\test.doc",
        file_size=2048,
        file_modified=datetime(2009, 12, 11, 16, 30, 0, tzinfo=timezone.utc),
        file_sha256="abc123",
        email_subject="Test Email",
        email_sent=datetime(2009, 12, 11, 16, 30, 30, tzinfo=timezone.utc),
        email_sender="test@example.com",
        attachment_name="test.doc",
        attachment_size=2048,
        time_delta_seconds=30.5,
        is_primary=True,
    )

    result = match.to_dict()

    assert result["file_path"] == "C:\\test.doc"
    assert result["file_size"] == 2048
    assert result["file_modified"] == "2009-12-11T16:30:00+00:00"
    assert result["file_sha256"] == "abc123"
    assert result["email_subject"] == "Test Email"
    assert result["email_sent"] == "2009-12-11T16:30:30+00:00"
    assert result["email_sender"] == "test@example.com"
    assert result["attachment_name"] == "test.doc"
    assert result["attachment_size"] == 2048
    assert result["time_delta_seconds"] == 30.5
    assert result["is_primary"] is True


def test_exfil_match_to_dict_with_none_timestamps():
    """Test ExfilMatch.to_dict() handles None timestamps correctly."""
    match = ExfilMatch(
        file_path="C:\\test.doc",
        file_size=1024,
        file_modified=None,
        file_sha256="abc123",
        email_subject="Test",
        email_sent=None,
        email_sender="test@example.com",
        attachment_name="test.doc",
        attachment_size=1024,
        time_delta_seconds=0.0,
    )

    result = match.to_dict()

    assert result["file_modified"] is None
    assert result["email_sent"] is None


# Tests for ExfilFinding.to_dict()


def test_exfil_finding_to_dict_serializes_all_fields():
    """Test ExfilFinding.to_dict() serializes all fields including matches."""
    match = ExfilMatch(
        file_path="C:\\test.doc",
        file_size=1024,
        file_modified=datetime(2009, 12, 11, 16, 30, 0, tzinfo=timezone.utc),
        file_sha256="abc123",
        email_subject="Test",
        email_sent=datetime(2009, 12, 11, 16, 30, 30, tzinfo=timezone.utc),
        email_sender="test@example.com",
        attachment_name="test.doc",
        attachment_size=1024,
        time_delta_seconds=30.0,
        is_primary=True,
    )

    finding = ExfilFinding(
        title="Test Finding",
        description="Test description",
        finding_type="indicator",
        severity="critical",
        confidence=0.95,
        confidence_label="Very High",
        category=FindingCategory.DATA_EXFILTRATION,
        matches=[match],
        evidence={"key": "value"},
        reasoning_chain=["step1", "step2"],
        contradictions=[],
        resolutions=[],
        confidence_calculation={"base": 0.95},
        artifact_sources=["mft", "pst"],
    )

    result = finding.to_dict()

    assert result["title"] == "Test Finding"
    assert result["description"] == "Test description"
    assert result["type"] == "indicator"
    assert result["severity"] == "critical"
    assert result["confidence"] == 0.95
    assert result["confidence_label"] == "Very High"
    assert result["category"] == "data_exfiltration"
    assert result["evidence"] == {"key": "value"}
    assert result["reasoning_chain"] == ["step1", "step2"]
    assert result["contradictions"] == []
    assert result["resolutions"] == []
    assert result["confidence_calculation"] == {"base": 0.95}
    assert result["artifact_sources"] == ["mft", "pst"]
    assert "detected_at" in result


# Tests for _compute_file_hash()


def test_compute_file_hash_success():
    """Test _compute_file_hash() successfully hashes file content."""
    content = b"Test file content"
    expected_hash = hashlib.sha256(content).hexdigest()

    mock_reader = Mock()
    mock_reader.read_file.return_value = content

    entry = create_test_mft_entry(file_path="C:\\test.txt")

    result = _compute_file_hash(mock_reader, entry)

    assert result == expected_hash
    mock_reader.read_file.assert_called_once_with(entry)


def test_compute_file_hash_returns_none_on_read_error():
    """Test _compute_file_hash() returns None when file cannot be read."""
    mock_reader = Mock()
    mock_reader.read_file.side_effect = Exception("Read error")

    entry = create_test_mft_entry(file_path="C:\\unreadable.txt")

    result = _compute_file_hash(mock_reader, entry)

    assert result is None


# Tests for _filter_mft_by_email_timeframe()


def test_filter_mft_by_email_timeframe_with_no_emails_returns_empty():
    """Test filtering with no emails returns empty list."""
    mft_entries = [create_test_mft_entry()]

    result = _filter_mft_by_email_timeframe(mft_entries, [])

    assert result == []


def test_filter_mft_by_email_timeframe_with_no_timestamps_returns_empty():
    """Test filtering with emails that have no timestamps returns empty."""
    mft_entries = [create_test_mft_entry()]
    emails = [create_test_email(submit_time=None, delivery_time=None)]

    result = _filter_mft_by_email_timeframe(mft_entries, emails)

    assert result == []


def test_filter_mft_by_email_timeframe_includes_files_within_buffer():
    """Test filtering includes files modified within buffer window."""
    # Email sent on 2009-12-11
    email_time = datetime(2009, 12, 11, 16, 0, 0, tzinfo=timezone.utc)
    email = create_test_email(submit_time=email_time)

    # File modified one day before (should be included with buffer_days=1)
    file_time = datetime(2009, 12, 10, 16, 0, 0, tzinfo=timezone.utc)
    mft_entry = create_test_mft_entry(fn_modified=file_time)

    result = _filter_mft_by_email_timeframe([mft_entry], [email], buffer_days=1)

    assert len(result) == 1
    assert result[0] == mft_entry


def test_filter_mft_by_email_timeframe_excludes_files_outside_buffer():
    """Test filtering excludes files modified outside buffer window."""
    # Email sent on 2009-12-11
    email_time = datetime(2009, 12, 11, 16, 0, 0, tzinfo=timezone.utc)
    email = create_test_email(submit_time=email_time)

    # File modified 3 days before (should be excluded with buffer_days=1)
    file_time = datetime(2009, 12, 8, 16, 0, 0, tzinfo=timezone.utc)
    mft_entry = create_test_mft_entry(fn_modified=file_time)

    result = _filter_mft_by_email_timeframe([mft_entry], [email], buffer_days=1)

    assert len(result) == 0


def test_filter_mft_by_email_timeframe_handles_multiple_emails():
    """Test filtering with multiple emails creates correct date range."""
    # Email 1: 2009-12-10
    email1 = create_test_email(
        submit_time=datetime(2009, 12, 10, 16, 0, 0, tzinfo=timezone.utc)
    )
    # Email 2: 2009-12-12
    email2 = create_test_email(
        submit_time=datetime(2009, 12, 12, 16, 0, 0, tzinfo=timezone.utc)
    )

    # File modified 2009-12-11 (between emails, should be included)
    file_time = datetime(2009, 12, 11, 16, 0, 0, tzinfo=timezone.utc)
    mft_entry = create_test_mft_entry(fn_modified=file_time)

    result = _filter_mft_by_email_timeframe([mft_entry], [email1, email2], buffer_days=1)

    assert len(result) == 1


def test_filter_mft_by_email_timeframe_uses_delivery_time_fallback():
    """Test filtering uses delivery_time when submit_time is None."""
    email_time = datetime(2009, 12, 11, 16, 0, 0, tzinfo=timezone.utc)
    email = create_test_email(submit_time=None, delivery_time=email_time)

    file_time = datetime(2009, 12, 11, 16, 0, 0, tzinfo=timezone.utc)
    mft_entry = create_test_mft_entry(fn_modified=file_time)

    result = _filter_mft_by_email_timeframe([mft_entry], [email], buffer_days=1)

    assert len(result) == 1


# Tests for _correlate_hashes()


def test_correlate_hashes_with_empty_file_hashes_returns_empty():
    """Test correlation with no file hashes returns empty list."""
    email = create_test_email(
        submit_time=datetime(2009, 12, 11, 16, 30, 0, tzinfo=timezone.utc),
        attachments=[create_test_attachment(sha256="abc123")],
    )

    result = _correlate_hashes({}, [email], time_window_seconds=300)

    assert result == []


def test_correlate_hashes_with_no_attachments_returns_empty():
    """Test correlation with emails that have no attachments returns empty."""
    mft_entry = create_test_mft_entry()
    file_hashes = {"abc123": (mft_entry, "abc123")}
    email = create_test_email(
        submit_time=datetime(2009, 12, 11, 16, 30, 0, tzinfo=timezone.utc),
        attachments=[],
    )

    result = _correlate_hashes(file_hashes, [email], time_window_seconds=300)

    assert result == []


def test_correlate_hashes_with_no_email_timestamp_skips_email():
    """Test correlation skips emails with no timestamp."""
    mft_entry = create_test_mft_entry()
    file_hashes = {"abc123": (mft_entry, "abc123")}
    email = create_test_email(
        submit_time=None,
        delivery_time=None,
        attachments=[create_test_attachment(sha256="abc123")],
    )

    result = _correlate_hashes(file_hashes, [email], time_window_seconds=300)

    assert result == []


def test_correlate_hashes_with_no_hash_match_returns_empty():
    """Test correlation with non-matching hashes returns empty."""
    mft_entry = create_test_mft_entry()
    file_hashes = {"abc123": (mft_entry, "abc123")}
    email = create_test_email(
        submit_time=datetime(2009, 12, 11, 16, 30, 0, tzinfo=timezone.utc),
        attachments=[create_test_attachment(sha256="different_hash")],
    )

    result = _correlate_hashes(file_hashes, [email], time_window_seconds=300)

    assert result == []


def test_correlate_hashes_with_no_file_timestamp_skips_entry():
    """Test correlation skips MFT entries with no modification time."""
    mft_entry = create_test_mft_entry(fn_modified=None, si_modified=None)
    file_hashes = {"abc123": (mft_entry, "abc123")}
    email = create_test_email(
        submit_time=datetime(2009, 12, 11, 16, 30, 0, tzinfo=timezone.utc),
        attachments=[create_test_attachment(sha256="abc123")],
    )

    result = _correlate_hashes(file_hashes, [email], time_window_seconds=300)

    assert result == []


def test_correlate_hashes_matches_file_to_email_within_time_window():
    """Test hash correlation finds match within time window."""
    file_time = datetime(2009, 12, 11, 16, 30, 0, tzinfo=timezone.utc)
    mft_entry = create_test_mft_entry(
        file_path="C:\\test.doc", file_size=2048, fn_modified=file_time
    )
    file_hashes = {"abc123": (mft_entry, "abc123")}

    email_time = datetime(2009, 12, 11, 16, 30, 30, tzinfo=timezone.utc)
    email = create_test_email(
        subject="Test Email",
        submit_time=email_time,
        sender_email="sender@test.com",
        attachments=[create_test_attachment(name="test.doc", size=2048, sha256="abc123")],
    )

    result = _correlate_hashes(file_hashes, [email], time_window_seconds=300)

    assert len(result) == 1
    match = result[0]
    assert "test.doc" in match.file_path
    assert match.file_size == 2048
    assert match.file_sha256 == "abc123"
    assert match.email_subject == "Test Email"
    assert match.email_sender == "sender@test.com"
    assert match.attachment_name == "test.doc"
    assert match.time_delta_seconds == 30.0


def test_correlate_hashes_excludes_negative_time_delta():
    """Test correlation excludes matches where email was sent before file modification."""
    file_time = datetime(2009, 12, 11, 16, 30, 0, tzinfo=timezone.utc)
    mft_entry = create_test_mft_entry(fn_modified=file_time)
    file_hashes = {"abc123": (mft_entry, "abc123")}

    # Email sent 30 seconds BEFORE file modification (negative delta)
    email_time = datetime(2009, 12, 11, 16, 29, 30, tzinfo=timezone.utc)
    email = create_test_email(
        submit_time=email_time, attachments=[create_test_attachment(sha256="abc123")]
    )

    result = _correlate_hashes(file_hashes, [email], time_window_seconds=300)

    assert len(result) == 0


def test_correlate_hashes_excludes_time_delta_beyond_window():
    """Test correlation excludes matches beyond time window."""
    file_time = datetime(2009, 12, 11, 16, 30, 0, tzinfo=timezone.utc)
    mft_entry = create_test_mft_entry(fn_modified=file_time)
    file_hashes = {"abc123": (mft_entry, "abc123")}

    # Email sent 400 seconds after file modification (beyond 300s window)
    email_time = datetime(2009, 12, 11, 16, 36, 40, tzinfo=timezone.utc)
    email = create_test_email(
        submit_time=email_time, attachments=[create_test_attachment(sha256="abc123")]
    )

    result = _correlate_hashes(file_hashes, [email], time_window_seconds=300)

    assert len(result) == 0


# Tests for _build_reasoning()


def test_build_reasoning_includes_all_stats():
    """Test _build_reasoning() includes all statistics."""
    stats = {
        "total_mft_entries": 1000,
        "candidates": 50,
        "hashed": 45,
        "skipped": 5,
        "total_emails": 10,
        "total_attachments": 15,
    }

    match = ExfilMatch(
        file_path="C:\\test.doc",
        file_size=2048,
        file_modified=datetime(2009, 12, 11, 16, 30, 0, tzinfo=timezone.utc),
        file_sha256="abc123def456",
        email_subject="Test Email",
        email_sent=datetime(2009, 12, 11, 16, 30, 30, tzinfo=timezone.utc),
        email_sender="test@example.com",
        attachment_name="test.doc",
        attachment_size=2048,
        time_delta_seconds=30.0,
        is_primary=True,
    )

    result = _build_reasoning([match], stats)

    assert len(result) >= 5
    assert "1000 MFT entries" in result[0]
    assert "50 files modified" in result[0]
    assert "Hashed 45 files" in result[1]
    assert "skipped 5" in result[1]
    assert "10 emails" in result[2]
    assert "15 attachments" in result[2]
    assert "1 file-to-email correlation" in result[3]


def test_build_reasoning_marks_primary_match():
    """Test _build_reasoning() marks primary match."""
    stats = {
        "total_mft_entries": 100,
        "candidates": 10,
        "hashed": 10,
        "skipped": 0,
        "total_emails": 5,
        "total_attachments": 5,
    }

    match = ExfilMatch(
        file_path="C:\\test.doc",
        file_size=1024,
        file_modified=datetime(2009, 12, 11, 16, 30, 0, tzinfo=timezone.utc),
        file_sha256="abc123",
        email_subject="Test",
        email_sent=datetime(2009, 12, 11, 16, 30, 30, tzinfo=timezone.utc),
        email_sender="test@example.com",
        attachment_name="test.doc",
        attachment_size=1024,
        time_delta_seconds=30.0,
        is_primary=True,
    )

    result = _build_reasoning([match], stats)

    # Find the match detail line
    match_line = [line for line in result if "Match 1" in line][0]
    assert "(PRIMARY)" in match_line


# Tests for _build_evidence()


def test_build_evidence_includes_all_stats_and_matches():
    """Test _build_evidence() includes all statistics and match details."""
    stats = {
        "total_mft_entries": 1000,
        "candidates": 50,
        "hashed": 45,
        "skipped": 5,
        "total_emails": 10,
        "total_attachments": 15,
    }

    match = ExfilMatch(
        file_path="C:\\test.doc",
        file_size=2048,
        file_modified=datetime(2009, 12, 11, 16, 30, 0, tzinfo=timezone.utc),
        file_sha256="abc123",
        email_subject="Test Email",
        email_sent=datetime(2009, 12, 11, 16, 30, 30, tzinfo=timezone.utc),
        email_sender="test@example.com",
        attachment_name="test.doc",
        attachment_size=2048,
        time_delta_seconds=30.0,
    )

    result = _build_evidence([match], stats)

    assert result["total_mft_entries"] == 1000
    assert result["filtered_candidates"] == 50
    assert result["files_hashed"] == 45
    assert result["files_skipped"] == 5
    assert result["total_emails"] == 10
    assert result["total_attachments"] == 15
    assert result["matches_found"] == 1
    assert result["time_window_seconds"] == 300
    assert len(result["correlations"]) == 1


# Tests for detect_exfiltration()


def test_detect_exfiltration_with_no_candidates_returns_none():
    """Test detect_exfiltration() returns None when no MFT candidates in timeframe."""
    image_path = Path("/tmp/test.e01")
    mft_entries = [
        create_test_mft_entry(
            fn_modified=datetime(2009, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        )
    ]
    emails = [
        create_test_email(
            submit_time=datetime(2009, 12, 11, 16, 0, 0, tzinfo=timezone.utc)
        )
    ]

    result = detect_exfiltration(image_path, mft_entries, emails)

    assert result is None


def test_detect_exfiltration_with_no_successful_hashes_returns_none():
    """Test detect_exfiltration() returns None when no files can be hashed."""
    image_path = Path("/tmp/test.e01")

    file_time = datetime(2009, 12, 11, 16, 0, 0, tzinfo=timezone.utc)
    mft_entries = [create_test_mft_entry(fn_modified=file_time)]
    emails = [
        create_test_email(submit_time=datetime(2009, 12, 11, 16, 0, 0, tzinfo=timezone.utc))
    ]

    with patch(
        "sift_find_evil.disk.exfil_detector.ImageContentReader"
    ) as mock_reader_class:
        mock_reader = MagicMock()
        mock_reader.__enter__.return_value = mock_reader
        mock_reader.__exit__.return_value = None
        # Simulate read failure for all files
        mock_reader.read_file.side_effect = Exception("Read error")
        mock_reader_class.return_value = mock_reader

        result = detect_exfiltration(image_path, mft_entries, emails)

    assert result is None


def test_detect_exfiltration_with_no_correlations_returns_none():
    """Test detect_exfiltration() returns None when no hash matches found."""
    image_path = Path("/tmp/test.e01")

    file_time = datetime(2009, 12, 11, 16, 0, 0, tzinfo=timezone.utc)
    mft_entries = [create_test_mft_entry(fn_modified=file_time)]

    email_time = datetime(2009, 12, 11, 16, 0, 30, tzinfo=timezone.utc)
    emails = [
        create_test_email(
            submit_time=email_time,
            attachments=[create_test_attachment(sha256="different_hash")],
        )
    ]

    with patch(
        "sift_find_evil.disk.exfil_detector.ImageContentReader"
    ) as mock_reader_class:
        mock_reader = MagicMock()
        mock_reader.__enter__.return_value = mock_reader
        mock_reader.__exit__.return_value = None
        mock_reader.read_file.return_value = b"test content"
        mock_reader_class.return_value = mock_reader

        result = detect_exfiltration(image_path, mft_entries, emails)

    assert result is None


def test_detect_exfiltration_returns_finding_with_correlation():
    """Test detect_exfiltration() returns finding when correlation found."""
    image_path = Path("/tmp/test.e01")

    file_content = b"Sensitive data"
    file_hash = hashlib.sha256(file_content).hexdigest()
    file_time = datetime(2009, 12, 11, 16, 30, 0, tzinfo=timezone.utc)
    mft_entries = [
        create_test_mft_entry(
            file_path="C:\\sensitive.doc", file_size=len(file_content), fn_modified=file_time
        )
    ]

    email_time = datetime(2009, 12, 11, 16, 30, 30, tzinfo=timezone.utc)
    emails = [
        create_test_email(
            subject="Sending doc",
            submit_time=email_time,
            sender_email="attacker@evil.com",
            attachments=[
                create_test_attachment(name="sensitive.doc", size=len(file_content), sha256=file_hash)
            ],
        )
    ]

    with patch(
        "sift_find_evil.disk.exfil_detector.ImageContentReader"
    ) as mock_reader_class:
        mock_reader = MagicMock()
        mock_reader.__enter__.return_value = mock_reader
        mock_reader.__exit__.return_value = None
        mock_reader.read_file.return_value = file_content
        mock_reader_class.return_value = mock_reader

        result = detect_exfiltration(image_path, mft_entries, emails)

    assert result is not None
    assert isinstance(result, ExfilFinding)
    assert result.category == FindingCategory.DATA_EXFILTRATION
    assert result.severity == "critical"
    assert result.confidence >= 0.85
    assert len(result.matches) == 1
    assert result.matches[0].is_primary is True
    assert result.matches[0].time_delta_seconds == 30.0


def test_detect_exfiltration_marks_primary_match_with_shortest_delta():
    """Test detect_exfiltration() marks match with shortest time delta as primary."""
    image_path = Path("/tmp/test.e01")

    # Create two files with different time deltas
    file_content = b"test"
    file_hash = hashlib.sha256(file_content).hexdigest()

    # File 1: 10 second delta (should be primary)
    file1_time = datetime(2009, 12, 11, 16, 0, 0, tzinfo=timezone.utc)
    mft1 = create_test_mft_entry(
        file_path="C:\\file1.txt", fn_modified=file1_time
    )

    # File 2: 50 second delta
    file2_time = datetime(2009, 12, 11, 16, 0, 0, tzinfo=timezone.utc)
    mft2 = create_test_mft_entry(
        file_path="C:\\file2.txt", fn_modified=file2_time
    )

    # Email 1: 10 seconds after file1
    email1_time = datetime(2009, 12, 11, 16, 0, 10, tzinfo=timezone.utc)
    email1 = create_test_email(
        subject="Email 1",
        submit_time=email1_time,
        attachments=[create_test_attachment(sha256=file_hash)],
    )

    # Email 2: 50 seconds after file2
    email2_time = datetime(2009, 12, 11, 16, 0, 50, tzinfo=timezone.utc)
    email2 = create_test_email(
        subject="Email 2",
        submit_time=email2_time,
        attachments=[create_test_attachment(sha256=file_hash)],
    )

    with patch(
        "sift_find_evil.disk.exfil_detector.ImageContentReader"
    ) as mock_reader_class:
        mock_reader = MagicMock()
        mock_reader.__enter__.return_value = mock_reader
        mock_reader.__exit__.return_value = None
        mock_reader.read_file.return_value = file_content
        mock_reader_class.return_value = mock_reader

        result = detect_exfiltration(image_path, [mft1, mft2], [email1, email2])

    assert result is not None
    assert len(result.matches) == 2

    # First match should be primary (shortest delta)
    primary_match = result.matches[0]
    assert primary_match.is_primary is True
    assert primary_match.time_delta_seconds == 10.0

    # Second match should not be primary
    assert result.matches[1].is_primary is False


def test_detect_exfiltration_confidence_calculation_for_immediate_exfil():
    """Test detect_exfiltration() calculates Very High confidence for immediate exfil."""
    image_path = Path("/tmp/test.e01")

    file_content = b"test"
    file_hash = hashlib.sha256(file_content).hexdigest()
    file_time = datetime(2009, 12, 11, 16, 30, 0, tzinfo=timezone.utc)
    mft_entries = [create_test_mft_entry(fn_modified=file_time)]

    # Email sent 30 seconds after file modification (within 60s threshold)
    email_time = datetime(2009, 12, 11, 16, 30, 30, tzinfo=timezone.utc)
    emails = [
        create_test_email(
            submit_time=email_time,
            attachments=[create_test_attachment(sha256=file_hash)],
        )
    ]

    with patch(
        "sift_find_evil.disk.exfil_detector.ImageContentReader"
    ) as mock_reader_class:
        mock_reader = MagicMock()
        mock_reader.__enter__.return_value = mock_reader
        mock_reader.__exit__.return_value = None
        mock_reader.read_file.return_value = file_content
        mock_reader_class.return_value = mock_reader

        result = detect_exfiltration(image_path, mft_entries, emails)

    assert result is not None
    assert result.confidence == 0.95
    assert result.confidence_label == "Very High"
