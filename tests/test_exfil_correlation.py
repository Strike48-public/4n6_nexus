"""Unit tests for EXFIL_CORRELATION detector (SFE-3)."""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta


from sift_find_evil.parsers.mft_parser import MFTEntry
from sift_find_evil.parsers.pst_parser import Attachment, EmailMessage
from sift_find_evil.self_correction.contradiction_detector import (
    ContradictionDetector,
    ContradictionType,
)
from sift_find_evil.self_correction.engine import SelfCorrectionEngine
from sift_find_evil.findings import FindingCategory


def make_mft_entry(
    entry_number: int,
    file_name: str,
    file_size: int,
    si_created: datetime,
    content_reader=None,
) -> MFTEntry:
    """Helper to create MFT entries for tests."""
    return MFTEntry(
        entry_number=entry_number,
        file_name=file_name,
        parent_path="C:\\Users\\Test\\Desktop",
        file_path=f"C:\\Users\\Test\\Desktop\\{file_name}",
        file_size=file_size,
        is_directory=False,
        in_use=True,
        si_created=si_created,
        si_modified=None,
        si_accessed=None,
        si_mft_modified=None,
        fn_created=si_created,
        fn_modified=None,
        fn_accessed=None,
        fn_mft_modified=None,
        content_reader=content_reader,
    )


def make_email(
    subject: str,
    submit_time: datetime,
    attachments: list[Attachment],
) -> EmailMessage:
    """Helper to create EmailMessage for tests."""
    return EmailMessage(
        folder="Sent Items",
        submit_time=submit_time,
        delivery_time=None,
        sender_name="Test User",
        sender_email="test@example.com",
        subject=subject,
        transport_headers="",
        body_preview="",
        attachments=tuple(attachments),
    )


def test_hash_match_inside_window():
    """EXFIL_CORRELATION fires when on-disk file hash matches email attachment hash within 5 minutes."""
    file_content = b"This is the file content."
    file_hash = hashlib.sha256(file_content).hexdigest()

    save_time = datetime(2023, 5, 10, 10, 0, 0)
    send_time = save_time + timedelta(seconds=44)  # Jean case window

    def fake_reader(entry: MFTEntry) -> bytes:
        return file_content

    mft_entry = make_mft_entry(
        entry_number=100,
        file_name="document.xlsx",
        file_size=len(file_content),
        si_created=save_time,
        content_reader=fake_reader,
    )

    attachment = Attachment(
        name="document.xlsx", size=len(file_content), sha256=file_hash
    )
    email = make_email(
        subject="Here is the file", submit_time=send_time, attachments=[attachment]
    )

    detector = ContradictionDetector()
    contradictions = detector.detect_save_then_exfil(
        [mft_entry], [email], content_reader=fake_reader
    )

    assert len(contradictions) == 1
    assert contradictions[0].type == ContradictionType.EXFIL_CORRELATION
    assert contradictions[0].details["match_type"] == "hash"
    assert contradictions[0].details["delta_seconds"] == 44.0


def test_hash_match_outside_window():
    """No finding when file is saved more than 5 minutes before email."""
    file_content = b"File content"
    file_hash = hashlib.sha256(file_content).hexdigest()

    save_time = datetime(2023, 5, 10, 10, 0, 0)
    send_time = save_time + timedelta(
        seconds=400
    )  # 6.67 minutes — outside default 300s window

    def fake_reader(entry: MFTEntry) -> bytes:
        return file_content

    mft_entry = make_mft_entry(
        entry_number=200,
        file_name="old_file.txt",
        file_size=len(file_content),
        si_created=save_time,
        content_reader=fake_reader,
    )

    attachment = Attachment(
        name="old_file.txt", size=len(file_content), sha256=file_hash
    )
    email = make_email(
        subject="Sending old file", submit_time=send_time, attachments=[attachment]
    )

    detector = ContradictionDetector()
    contradictions = detector.detect_save_then_exfil(
        [mft_entry], [email], content_reader=fake_reader
    )

    assert len(contradictions) == 0, "File saved >5min before email should not match"


def test_size_name_fallback():
    """When content_reader is None, fall back to size+name matching with lower confidence."""
    save_time = datetime(2023, 5, 10, 10, 0, 0)
    send_time = save_time + timedelta(seconds=60)

    mft_entry = make_mft_entry(
        entry_number=300,
        file_name="report.pdf",
        file_size=5000,
        si_created=save_time,
        content_reader=None,  # No hash available
    )

    attachment = Attachment(name="report.pdf", size=5000, sha256="dummy_hash")
    email = make_email(
        subject="Report attached", submit_time=send_time, attachments=[attachment]
    )

    detector = ContradictionDetector()
    # content_reader=None triggers size+name fallback
    contradictions = detector.detect_save_then_exfil(
        [mft_entry], [email], content_reader=None
    )

    assert len(contradictions) == 1
    assert contradictions[0].type == ContradictionType.EXFIL_CORRELATION
    assert contradictions[0].details["match_type"] == "size_name_fallback"
    assert contradictions[0].details["delta_seconds"] == 60.0


def test_no_match_wrong_size():
    """Size+name fallback does not match when sizes differ."""
    save_time = datetime(2023, 5, 10, 10, 0, 0)
    send_time = save_time + timedelta(seconds=30)

    mft_entry = make_mft_entry(
        entry_number=400,
        file_name="file.txt",
        file_size=1000,
        si_created=save_time,
    )

    attachment = Attachment(name="file.txt", size=2000, sha256="hash")  # Different size
    email = make_email(
        subject="Sending file", submit_time=send_time, attachments=[attachment]
    )

    detector = ContradictionDetector()
    contradictions = detector.detect_save_then_exfil(
        [mft_entry], [email], content_reader=None
    )

    assert len(contradictions) == 0, "Different sizes should not match in fallback mode"


def test_engine_generates_exfil_finding():
    """SelfCorrectionEngine.analyze() with emails parameter generates EXFIL_CORRELATION finding."""
    file_content = b"Sensitive data"
    file_hash = hashlib.sha256(file_content).hexdigest()

    save_time = datetime(2023, 5, 10, 10, 0, 0)
    send_time = save_time + timedelta(seconds=50)

    def fake_reader(entry: MFTEntry) -> bytes:
        return file_content

    mft_entry = make_mft_entry(
        entry_number=500,
        file_name="data.xlsx",
        file_size=len(file_content),
        si_created=save_time,
        content_reader=fake_reader,
    )

    attachment = Attachment(name="data.xlsx", size=len(file_content), sha256=file_hash)
    email = make_email(
        subject="Data attached", submit_time=send_time, attachments=[attachment]
    )

    engine = SelfCorrectionEngine()
    findings = engine.analyze(
        mft_entries=[mft_entry],
        prefetch_entries=[],
        event_log_entries=[],
        content_reader=fake_reader,
        emails=[email],
    )

    # Should produce exactly one finding
    assert len(findings) == 1
    finding = findings[0]

    assert finding.category == FindingCategory.DATA_EXFILTRATION
    assert finding.severity == "critical"
    assert finding.confidence >= 0.90, "Hash match should have high confidence"
    assert "SHA-256" in " ".join(finding.reasoning_chain)


def test_engine_preserves_existing_behavior_without_emails():
    """When emails=None, engine behaves as before (no EXFIL_CORRELATION)."""
    mft_entry = make_mft_entry(
        entry_number=600,
        file_name="normal.txt",
        file_size=100,
        si_created=datetime(2023, 5, 10, 10, 0, 0),
    )

    engine = SelfCorrectionEngine()
    findings = engine.analyze(
        mft_entries=[mft_entry],
        prefetch_entries=[],
        event_log_entries=[],
        content_reader=None,
        emails=None,  # No PST provided
    )

    # Should produce zero findings (no process-execution contradictions, no exfil)
    assert len(findings) == 0


def test_confidence_score_hash_match():
    """Hash match produces confidence 0.95 (per acceptance criteria)."""
    file_content = b"Test"
    file_hash = hashlib.sha256(file_content).hexdigest()

    save_time = datetime(2023, 5, 10, 10, 0, 0)
    send_time = save_time + timedelta(seconds=10)

    def fake_reader(entry: MFTEntry) -> bytes:
        return file_content

    mft_entry = make_mft_entry(
        entry_number=700,
        file_name="test.txt",
        file_size=len(file_content),
        si_created=save_time,
        content_reader=fake_reader,
    )

    attachment = Attachment(name="test.txt", size=len(file_content), sha256=file_hash)
    email = make_email(subject="Test", submit_time=send_time, attachments=[attachment])

    engine = SelfCorrectionEngine()
    findings = engine.analyze(
        mft_entries=[mft_entry],
        prefetch_entries=[],
        event_log_entries=[],
        content_reader=fake_reader,
        emails=[email],
    )

    assert findings[0].confidence == 0.95


def test_confidence_score_size_name_fallback():
    """Size+name fallback produces confidence 0.65 (per acceptance criteria)."""
    save_time = datetime(2023, 5, 10, 10, 0, 0)
    send_time = save_time + timedelta(seconds=10)

    mft_entry = make_mft_entry(
        entry_number=800,
        file_name="fallback.txt",
        file_size=500,
        si_created=save_time,
    )

    attachment = Attachment(name="fallback.txt", size=500, sha256="hash")
    email = make_email(
        subject="Fallback test", submit_time=send_time, attachments=[attachment]
    )

    engine = SelfCorrectionEngine()
    findings = engine.analyze(
        mft_entries=[mft_entry],
        prefetch_entries=[],
        event_log_entries=[],
        content_reader=None,  # Triggers fallback
        emails=[email],
    )

    assert findings[0].confidence == 0.65


# ============================================================================
# Hash-Based Exfiltration Detection Edge Cases (lines 446-480)
# ============================================================================


def test_detect_save_then_exfil_hash_match_returns_critical():
    """Hash match produces CRITICAL severity finding."""
    file_content = b"Sensitive data"
    file_hash = hashlib.sha256(file_content).hexdigest()

    save_time = datetime(2023, 5, 10, 10, 0, 0)
    send_time = save_time + timedelta(seconds=60)

    def fake_reader(entry):
        return file_content

    mft_entry = make_mft_entry(
        entry_number=900,
        file_name="data.xlsx",
        file_size=len(file_content),
        si_created=save_time,
    )

    attachment = Attachment(name="data.xlsx", size=len(file_content), sha256=file_hash)
    email = make_email(subject="Data", submit_time=send_time, attachments=[attachment])

    detector = ContradictionDetector()
    contradictions = detector.detect_save_then_exfil(
        [mft_entry], [email], content_reader=fake_reader
    )

    assert len(contradictions) == 1
    assert contradictions[0].severity.value == "critical"
    assert contradictions[0].details["match_type"] == "hash"


def test_detect_save_then_exfil_hash_match_within_time_window():
    """Hash match within 300s window produces finding."""
    file_content = b"Test"
    file_hash = hashlib.sha256(file_content).hexdigest()

    save_time = datetime(2023, 5, 10, 10, 0, 0)
    send_time = save_time + timedelta(seconds=299)  # Just under 5min

    def fake_reader(entry):
        return file_content

    mft_entry = make_mft_entry(
        entry_number=901,
        file_name="test.txt",
        file_size=len(file_content),
        si_created=save_time,
    )

    attachment = Attachment(name="test.txt", size=len(file_content), sha256=file_hash)
    email = make_email(subject="Test", submit_time=send_time, attachments=[attachment])

    detector = ContradictionDetector()
    contradictions = detector.detect_save_then_exfil(
        [mft_entry], [email], content_reader=fake_reader, window_seconds=300
    )

    assert len(contradictions) == 1
    assert contradictions[0].details["delta_seconds"] == 299.0


def test_detect_save_then_exfil_hash_match_outside_window_skips():
    """Hash match outside time window does not produce finding."""
    file_content = b"Old file"
    file_hash = hashlib.sha256(file_content).hexdigest()

    save_time = datetime(2023, 5, 10, 10, 0, 0)
    send_time = save_time + timedelta(seconds=301)  # Just over 5min

    def fake_reader(entry):
        return file_content

    mft_entry = make_mft_entry(
        entry_number=902,
        file_name="old.txt",
        file_size=len(file_content),
        si_created=save_time,
    )

    attachment = Attachment(name="old.txt", size=len(file_content), sha256=file_hash)
    email = make_email(subject="Old", submit_time=send_time, attachments=[attachment])

    detector = ContradictionDetector()
    contradictions = detector.detect_save_then_exfil(
        [mft_entry], [email], content_reader=fake_reader, window_seconds=300
    )

    assert len(contradictions) == 0, "Files outside window should not match"


def test_detect_save_then_exfil_no_matching_hash_skips():
    """Different hashes do not produce finding when sizes also differ."""
    file_content_1 = b"File 1"
    file_content_2 = b"File 2 with different content"
    hash_2 = hashlib.sha256(file_content_2).hexdigest()

    save_time = datetime(2023, 5, 10, 10, 0, 0)
    send_time = save_time + timedelta(seconds=60)

    def fake_reader(entry):
        return file_content_1  # Different content

    mft_entry = make_mft_entry(
        entry_number=903,
        file_name="file.txt",
        file_size=len(file_content_1),  # Size 6
        si_created=save_time,
    )

    attachment = Attachment(
        name="file.txt",
        size=len(file_content_2),  # Size 29 (different)
        sha256=hash_2,
    )
    email = make_email(subject="File", submit_time=send_time, attachments=[attachment])

    detector = ContradictionDetector()
    contradictions = detector.detect_save_then_exfil(
        [mft_entry], [email], content_reader=fake_reader
    )

    assert len(contradictions) == 0, "Different hashes and sizes should not match"


def test_detect_save_then_exfil_email_has_no_submit_time_skips():
    """Email without submit_time is skipped gracefully."""
    file_content = b"Test"
    file_hash = hashlib.sha256(file_content).hexdigest()

    save_time = datetime(2023, 5, 10, 10, 0, 0)

    def fake_reader(entry):
        return file_content

    mft_entry = make_mft_entry(
        entry_number=904,
        file_name="test.txt",
        file_size=len(file_content),
        si_created=save_time,
    )

    attachment = Attachment(name="test.txt", size=len(file_content), sha256=file_hash)
    # Email with no submit_time
    email = EmailMessage(
        folder="Drafts",
        submit_time=None,  # No submit time
        delivery_time=None,
        sender_name="Test",
        sender_email="test@example.com",
        subject="Test",
        transport_headers="",
        body_preview="",
        attachments=(attachment,),
    )

    detector = ContradictionDetector()
    contradictions = detector.detect_save_then_exfil(
        [mft_entry], [email], content_reader=fake_reader
    )

    assert len(contradictions) == 0, "Emails without submit_time should be skipped"


# ============================================================================
# Size-Based Exfiltration Fallback Edge Cases (lines 481-523)
# ============================================================================


def test_detect_save_then_exfil_size_name_fallback_returns_high():
    """Size+name fallback produces HIGH severity finding."""
    save_time = datetime(2023, 5, 10, 10, 0, 0)
    send_time = save_time + timedelta(seconds=60)

    mft_entry = make_mft_entry(
        entry_number=905,
        file_name="report.pdf",
        file_size=5000,
        si_created=save_time,
    )

    attachment = Attachment(name="report.pdf", size=5000, sha256="dummy")
    email = make_email(subject="Report", submit_time=send_time, attachments=[attachment])

    detector = ContradictionDetector()
    contradictions = detector.detect_save_then_exfil(
        [mft_entry], [email], content_reader=None  # Triggers fallback
    )

    assert len(contradictions) == 1
    assert contradictions[0].severity.value == "high"
    assert contradictions[0].details["match_type"] == "size_name_fallback"


def test_detect_save_then_exfil_size_mismatch_skips():
    """Size mismatch in fallback mode does not produce finding."""
    save_time = datetime(2023, 5, 10, 10, 0, 0)
    send_time = save_time + timedelta(seconds=60)

    mft_entry = make_mft_entry(
        entry_number=906,
        file_name="file.txt",
        file_size=1000,
        si_created=save_time,
    )

    attachment = Attachment(name="file.txt", size=2000, sha256="hash")
    email = make_email(subject="File", submit_time=send_time, attachments=[attachment])

    detector = ContradictionDetector()
    contradictions = detector.detect_save_then_exfil(
        [mft_entry], [email], content_reader=None
    )

    assert len(contradictions) == 0


def test_detect_save_then_exfil_name_mismatch_skips():
    """Name mismatch in fallback mode does not produce finding."""
    save_time = datetime(2023, 5, 10, 10, 0, 0)
    send_time = save_time + timedelta(seconds=60)

    mft_entry = make_mft_entry(
        entry_number=907,
        file_name="file1.txt",
        file_size=1000,
        si_created=save_time,
    )

    attachment = Attachment(name="file2.txt", size=1000, sha256="hash")
    email = make_email(subject="File", submit_time=send_time, attachments=[attachment])

    detector = ContradictionDetector()
    contradictions = detector.detect_save_then_exfil(
        [mft_entry], [email], content_reader=None
    )

    assert len(contradictions) == 0


def test_detect_save_then_exfil_file_outside_window_skips():
    """File saved outside time window does not match in fallback mode."""
    save_time = datetime(2023, 5, 10, 10, 0, 0)
    send_time = save_time + timedelta(seconds=400)

    mft_entry = make_mft_entry(
        entry_number=908,
        file_name="old.txt",
        file_size=1000,
        si_created=save_time,
    )

    attachment = Attachment(name="old.txt", size=1000, sha256="hash")
    email = make_email(subject="Old", submit_time=send_time, attachments=[attachment])

    detector = ContradictionDetector()
    contradictions = detector.detect_save_then_exfil(
        [mft_entry], [email], content_reader=None, window_seconds=300
    )

    assert len(contradictions) == 0


def test_detect_save_then_exfil_content_reader_exception_falls_back():
    """Content reader exception falls back to size+name matching."""
    file_hash = "abc123"
    save_time = datetime(2023, 5, 10, 10, 0, 0)
    send_time = save_time + timedelta(seconds=60)

    def failing_reader(entry):
        raise IOError("Disk read error")

    mft_entry = make_mft_entry(
        entry_number=909,
        file_name="corrupt.txt",
        file_size=100,
        si_created=save_time,
    )

    attachment = Attachment(name="corrupt.txt", size=100, sha256=file_hash)
    email = make_email(subject="Corrupt", submit_time=send_time, attachments=[attachment])

    detector = ContradictionDetector()
    contradictions = detector.detect_save_then_exfil(
        [mft_entry], [email], content_reader=failing_reader
    )

    # Hash read fails, but falls back to size+name matching
    assert len(contradictions) == 1
    assert contradictions[0].details["match_type"] == "size_name_fallback"


def test_detect_save_then_exfil_no_browser_download_time_skips():
    """MFT entry without si_created timestamp is skipped."""
    file_content = b"Test"
    file_hash = hashlib.sha256(file_content).hexdigest()

    send_time = datetime(2023, 5, 10, 10, 0, 0)

    def fake_reader(entry):
        return file_content

    # Entry with no si_created
    mft_entry = MFTEntry(
        entry_number=910,
        file_name="test.txt",
        parent_path="C:\\Users\\Test\\Desktop",
        file_path="C:\\Users\\Test\\Desktop\\test.txt",
        file_size=len(file_content),
        is_directory=False,
        in_use=True,
        si_created=None,  # No creation time
        si_modified=None,
        si_accessed=None,
        si_mft_modified=None,
        fn_created=None,
        fn_modified=None,
        fn_accessed=None,
        fn_mft_modified=None,
    )

    attachment = Attachment(name="test.txt", size=len(file_content), sha256=file_hash)
    email = make_email(subject="Test", submit_time=send_time, attachments=[attachment])

    detector = ContradictionDetector()
    contradictions = detector.detect_save_then_exfil(
        [mft_entry], [email], content_reader=fake_reader
    )

    assert len(contradictions) == 0, "Entries without si_created should be skipped"
