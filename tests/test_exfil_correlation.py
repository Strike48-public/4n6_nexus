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
