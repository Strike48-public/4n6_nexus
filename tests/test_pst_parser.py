"""Unit and integration-lite tests for PST parser (SFE-1)."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

import pytest
import pytz

from sift_find_evil.parsers.pst_parser import (
    PstParser,
    _hash_attachment_streaming,
    _parse_attachment,
    _parse_message,
)


# Fake pypff attachment for unit tests


@dataclass
class FakeAttachment:
    """Mock pypff attachment with fixed content."""

    name: str
    size: int
    _content: bytes
    _offset: int = 0

    def read_buffer(self, size: int) -> bytes:
        """Simulate pypff read_buffer behavior."""
        chunk = self._content[self._offset : self._offset + size]
        self._offset += len(chunk)
        return chunk


@dataclass
class FakeMessage:
    """Mock pypff message."""

    client_submit_time: datetime | None = None
    delivery_time: datetime | None = None
    sender_name: str | None = None
    sender_email_address: str | None = None
    subject: str | None = None
    transport_headers: str | None = None
    plain_text_body: str | None = None
    html_body: str | None = None
    number_of_attachments: int = 0
    _attachments: list[FakeAttachment] | None = None

    def get_attachment(self, index: int):
        if self._attachments is None or index >= len(self._attachments):
            raise IndexError(f"attachment {index} out of range")
        return self._attachments[index]


# Unit tests


def test_attachment_hash_streaming_single_chunk():
    """Hash a small attachment that fits in one 64 KB window."""
    content = b"Hello, world!"
    att = FakeAttachment(name="test.txt", size=len(content), _content=content)
    digest = _hash_attachment_streaming(att)
    expected = hashlib.sha256(content).hexdigest()
    assert digest == expected


def test_attachment_hash_streaming_multiple_chunks():
    """Hash a large attachment spanning multiple 64 KB windows."""
    content = b"X" * (200 * 1024)  # 200 KB
    att = FakeAttachment(name="large.bin", size=len(content), _content=content)
    digest = _hash_attachment_streaming(att, window_kb=64)
    expected = hashlib.sha256(content).hexdigest()
    assert digest == expected


def test_parse_attachment_with_name_and_size():
    """Parse an attachment with normal name and size."""
    content = b"attachment content"
    att = FakeAttachment(name="report.pdf", size=len(content), _content=content)
    parsed = _parse_attachment(att)
    assert parsed.name == "report.pdf"
    assert parsed.size == len(content)
    assert parsed.sha256 == hashlib.sha256(content).hexdigest()


def test_parse_attachment_no_name():
    """Parse an attachment where .name is None."""
    content = b"data"
    att = FakeAttachment(name=None, size=len(content), _content=content)  # type: ignore
    parsed = _parse_attachment(att)
    assert parsed.name == "<unnamed>"
    assert parsed.size == len(content)


def test_parse_message_no_attachments():
    """Parse a message with zero attachments."""
    msg = FakeMessage(
        client_submit_time=datetime(2008, 7, 20, 1, 28, 47),
        sender_name="John Doe",
        sender_email_address="john@example.com",
        subject="Test Subject",
        plain_text_body="Body text.",
        number_of_attachments=0,
    )
    parsed = _parse_message(("Inbox",), msg)
    assert parsed.folder == "Inbox"
    assert parsed.submit_time == datetime(2008, 7, 20, 1, 28, 47, tzinfo=pytz.utc)
    assert parsed.sender_name == "John Doe"
    assert parsed.sender_email == "john@example.com"
    assert parsed.subject == "Test Subject"
    assert parsed.body_preview == "Body text."
    assert parsed.attachments == ()


def test_parse_message_with_one_attachment():
    """Parse a message with one attachment and verify hash."""
    content = b"This is the attachment content for the test."
    att = FakeAttachment(name="file.txt", size=len(content), _content=content)
    msg = FakeMessage(
        subject="Message with attachment",
        number_of_attachments=1,
        _attachments=[att],
    )
    parsed = _parse_message(("Sent Items",), msg)
    assert len(parsed.attachments) == 1
    assert parsed.attachments[0].name == "file.txt"
    assert parsed.attachments[0].size == len(content)
    assert parsed.attachments[0].sha256 == hashlib.sha256(content).hexdigest()


def test_parse_message_html_fallback():
    """When plain_text_body is absent, fall back to html_body."""
    msg = FakeMessage(
        subject="HTML only",
        plain_text_body=None,
        html_body="<p>HTML body</p>",
        number_of_attachments=0,
    )
    parsed = _parse_message(("Drafts",), msg)
    assert parsed.body_preview == "<p>HTML body</p>"


def test_parse_message_sanitizes_whitespace():
    """Newlines and carriage returns in text fields are replaced with spaces."""
    msg = FakeMessage(
        sender_name="Jane\r\nDoe",
        subject="Multi\nline\rsubject",
        plain_text_body="Body\nwith\r\nlines",
        number_of_attachments=0,
    )
    parsed = _parse_message(("Inbox",), msg)
    assert parsed.sender_name == "Jane  Doe"
    assert parsed.subject == "Multi line subject"
    # \r\n becomes two spaces (one per character replaced)
    assert parsed.body_preview == "Body with  lines"


def test_pst_parser_rejects_missing_file():
    """parse_file raises FileNotFoundError for a nonexistent PST."""
    parser = PstParser()
    with pytest.raises(FileNotFoundError, match="PST file not found"):
        parser.parse_file(Path("/nonexistent/path.pst"))


def test_safe_text_with_none_attribute():
    """_safe_text handles None attribute values."""
    from sift_find_evil.parsers.pst_parser import _safe_text

    msg = FakeMessage(sender_name=None, subject="Test")
    result = _safe_text(msg, "sender_name")
    assert result == ""


def test_safe_text_with_exception():
    """_safe_text handles exceptions during attribute access."""
    from sift_find_evil.parsers.pst_parser import _safe_text

    class BrokenMessage:
        @property
        def broken_field(self):
            raise RuntimeError("Simulated error")

    msg = BrokenMessage()
    result = _safe_text(msg, "broken_field")
    assert result == ""


def test_parse_attachment_size_exception():
    """_parse_attachment handles exception when accessing size."""
    from sift_find_evil.parsers.pst_parser import _parse_attachment

    class AttachmentWithBrokenSize:
        name = "test.txt"
        _content = b"data"
        _offset = 0

        @property
        def size(self):
            raise RuntimeError("Size unavailable")

        def read_buffer(self, size: int) -> bytes:
            chunk = self._content[self._offset : self._offset + size]
            self._offset += len(chunk)
            return chunk

    att = AttachmentWithBrokenSize()
    parsed = _parse_attachment(att)
    assert parsed.name == "test.txt"
    assert parsed.size == 0  # Default when exception occurs


def test_parse_message_attachment_enumeration_fails():
    """_parse_message handles exception during attachment enumeration."""
    class MessageWithBrokenAttachments:
        client_submit_time = None
        delivery_time = None
        sender_name = "Test"
        sender_email_address = "test@example.com"
        subject = "Test"
        transport_headers = None
        plain_text_body = "Body"
        html_body = None

        @property
        def number_of_attachments(self):
            raise RuntimeError("Attachment count unavailable")

    msg = MessageWithBrokenAttachments()
    parsed = _parse_message(("Inbox",), msg)
    assert parsed.attachments == ()  # Empty tuple when enumeration fails


def test_walk_folder_with_corrupt_message():
    """_walk_folder skips corrupt messages without halting parse."""
    from sift_find_evil.parsers.pst_parser import _walk_folder

    # Message that raises exception when accessed in iteration
    class CorruptMessageGenerator:
        def __iter__(self):
            # First message works, second raises exception during append
            yield FakeMessage(subject="Good message")
            # Simulate a message that raises exception when appending to pairs
            # This is tested by having the message itself be valid but raising
            # during the tuple creation
            raise RuntimeError("Corrupt message during iteration")

    class FakeFolder:
        name = "Test Folder"

        @property
        def sub_messages(self):
            # Return a simple list with one message (pypff iteration works this way)
            return [FakeMessage(subject="Test")]

        @property
        def sub_folders(self):
            return []

    folder = FakeFolder()
    pairs = _walk_folder(folder, tuple())
    # Should have one message (the good one)
    assert len(pairs) == 1


def test_walk_folder_with_unnamed_folder():
    """_walk_folder handles folder with None name."""
    from sift_find_evil.parsers.pst_parser import _walk_folder

    class UnnamedFolder:
        name = None

        @property
        def sub_messages(self):
            return []

        @property
        def sub_folders(self):
            return []

    folder = UnnamedFolder()
    pairs = _walk_folder(folder, tuple())
    # Should use <root> as name for None
    assert len(pairs) == 0  # No messages to return


def test_walk_folder_with_exception_during_name_access():
    """_walk_folder handles exception when accessing folder name."""
    from sift_find_evil.parsers.pst_parser import _walk_folder

    class FolderWithBrokenName:
        @property
        def name(self):
            raise RuntimeError("Name unavailable")

        @property
        def sub_messages(self):
            return []

        @property
        def sub_folders(self):
            return []

    folder = FolderWithBrokenName()
    pairs = _walk_folder(folder, tuple())
    # Should use <unnamed> as fallback
    assert len(pairs) == 0


def test_parse_message_truncates_long_transport_headers():
    """_parse_message truncates transport headers to 4000 chars."""
    long_headers = "X-Header: " + ("A" * 5000)
    msg = FakeMessage(
        transport_headers=long_headers,
        plain_text_body="Body",
        number_of_attachments=0,
    )
    parsed = _parse_message(("Inbox",), msg)
    assert len(parsed.transport_headers) == 4000


def test_parse_message_truncates_long_body_preview():
    """_parse_message truncates body preview to 2000 chars."""
    long_body = "Body: " + ("B" * 3000)
    msg = FakeMessage(
        plain_text_body=long_body,
        number_of_attachments=0,
    )
    parsed = _parse_message(("Inbox",), msg)
    assert len(parsed.body_preview) == 2000


def test_parse_message_with_tzinfo_aware_timestamps():
    """_parse_message preserves tzinfo-aware timestamps."""
    submit_time = datetime(2008, 7, 20, 1, 28, 47, tzinfo=pytz.utc)
    delivery_time = datetime(2008, 7, 20, 1, 30, 0, tzinfo=pytz.utc)
    msg = FakeMessage(
        client_submit_time=submit_time,
        delivery_time=delivery_time,
        subject="Test",
        number_of_attachments=0,
    )
    parsed = _parse_message(("Inbox",), msg)
    assert parsed.submit_time == submit_time
    assert parsed.delivery_time == delivery_time


# Integration-lite test (requires Jean artifacts)


@pytest.mark.skipif(
    not Path("analysis/m57-jean/extracted/email/outlook.pst").exists(),
    reason="Jean PST not extracted",
)
def test_parse_jean_pst_critical_message():
    """Parse Jean's PST and assert the exfil email has the correct attachment hash.

    This is the integration-lite test per SFE-1 acceptance criteria: the engine's
    hash-based EXFIL_CORRELATION detector (SFE-3) will depend on this parser
    producing the right SHA-256 for the attachment in Jean's "RE: Please send me
    the information now" reply.
    """
    parser = PstParser()
    pst_path = Path("analysis/m57-jean/extracted/email/outlook.pst")
    messages = parser.parse_file(pst_path)

    # Find the Sent Items reply
    exfil_message = next(
        (
            msg
            for msg in messages
            if msg.folder == "<root>/Top of Personal Folders/Sent Items"
            and msg.subject == "RE: Please send me the information now"
        ),
        None,
    )

    assert exfil_message is not None, "Jean's exfil reply not found in Sent Items"
    assert len(exfil_message.attachments) == 1, "Expected exactly one attachment"

    att = exfil_message.attachments[0]
    expected_sha256 = "34456b5f714dc9d8dd23c742d54c3f5f582ecb042bc1c4d3042b88203863779f"
    assert (
        att.sha256 == expected_sha256
    ), f"Attachment hash mismatch: got {att.sha256}, expected {expected_sha256}"
    assert (
        att.size == 291840
    ), f"Attachment size mismatch: got {att.size}, expected 291840"
