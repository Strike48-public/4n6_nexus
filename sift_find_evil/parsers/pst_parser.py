"""Production PST parser with attachment-level hash extraction.

Promotes `scripts/parse_jean_pst.py` to a first-class artifact source the engine
can consume. Emits frozen dataclasses with streaming SHA-256 computation for
attachments (no full-attachment-in-memory requirement).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Protocol


def _require_pypff():
    """Import pypff lazily so the package loads without the native libpff bindings.

    pypff (from `libpff-python`) is an optional native dependency only needed for
    PST email parsing. Importing it at module top-level would crash the entire CLI
    on systems without libpff installed. Defer the import to call time and raise an
    actionable error instead.
    """
    try:
        import pypff
    except ImportError as exc:  # pragma: no cover - exercised only without libpff
        raise ImportError(
            "PST parsing requires the 'libpff-python' package (provides pypff), "
            "which has native dependencies. Install it with "
            "'pip install libpff-python' or install the forensic extras: "
            "'pip install -r requirements-forensic.txt'."
        ) from exc
    return pypff


@dataclass(frozen=True)
class Attachment:
    """A single email attachment with its identifying metadata.

    The `sha256` field is computed via streaming read (64 KB window) so large
    attachments do not blow out memory.
    """

    name: str
    size: int
    sha256: str  # hex digest


@dataclass(frozen=True)
class EmailMessage:
    """A single parsed email message from a PST file.

    All text fields are sanitized (no CR/LF, leading/trailing whitespace stripped).
    Times are preserved as datetime objects from pypff (which returns them as
    datetime with no tzinfo — treat them as local to the PST's creation context).
    """

    folder: str  # slash-separated path from PST root
    submit_time: datetime | None
    delivery_time: datetime | None
    sender_name: str
    sender_email: str
    subject: str
    transport_headers: str  # truncated to 4000 chars
    body_preview: str  # plain or HTML fallback, truncated to 2000 chars
    attachments: tuple[Attachment, ...]


class PstFile(Protocol):
    """Duck-typed interface for pypff.file so tests can mock it."""

    def open(self, path: str) -> None:
        """Open PST file at given path."""
        ...

    def close(self) -> None:
        """Close PST file handle."""
        ...

    def get_root_folder(self) -> PstFolder:
        """Get root folder of PST hierarchy."""
        ...


class PstFolder(Protocol):
    """Duck-typed interface for pypff folder traversal."""

    @property
    def name(self) -> str | None:
        """Folder display name."""
        ...

    @property
    def sub_folders(self):
        """Iterator of child folders."""
        ...

    @property
    def sub_messages(self):
        """Iterator of messages in this folder."""
        ...


class PstMessage(Protocol):
    """Duck-typed interface for pypff message access."""

    @property
    def client_submit_time(self) -> datetime | None:
        """Timestamp when message was submitted by client."""
        ...

    @property
    def delivery_time(self) -> datetime | None:
        """Timestamp when message was delivered to server."""
        ...

    @property
    def sender_name(self) -> str | None:
        """Display name of message sender."""
        ...

    @property
    def sender_email_address(self) -> str | None:
        """Email address of message sender."""
        ...

    @property
    def subject(self) -> str | None:
        """Message subject line."""
        ...

    @property
    def transport_headers(self) -> str | None:
        """Raw SMTP transport headers."""
        ...

    @property
    def plain_text_body(self) -> str | None:
        """Plain text body content."""
        ...

    @property
    def html_body(self) -> str | None:
        """HTML body content."""
        ...

    @property
    def number_of_attachments(self) -> int:
        """Count of attachments in this message."""
        ...

    def get_attachment(self, index: int):
        """Get attachment at given index (0-based)."""
        ...


def _walk_folder(
    folder: PstFolder, parents: tuple[str, ...]
) -> list[tuple[tuple[str, ...], PstMessage]]:
    """Recursively walk PST folder tree, yielding (path_tuple, message) pairs.

    Exceptions during folder name resolution or message access are swallowed so
    one corrupted folder/message does not halt the entire parse.
    """
    try:
        name = folder.name or "<root>"
    except Exception:
        name = "<unnamed>"

    path = parents + (name,)
    pairs: list[tuple[tuple[str, ...], PstMessage]] = []

    for msg in folder.sub_messages:
        try:
            pairs.append((path, msg))
        except Exception:  # pragma: no cover - building/append of a (tuple, msg) pair cannot raise; iterator errors propagate from the for-loop
            # Corrupt message — skip it rather than halting the entire parse.
            continue

    for sub in folder.sub_folders:
        pairs.extend(_walk_folder(sub, path))

    return pairs


def _safe_text(obj, attr: str) -> str:
    """Extract a text attribute from a pypff object, sanitizing whitespace."""
    try:
        value = getattr(obj, attr)
        if value is None:
            return ""
        return str(value).replace("\r", " ").replace("\n", " ").strip()
    except Exception:
        return ""


def _hash_attachment_streaming(attachment, window_kb: int = 64) -> str:
    """Compute SHA-256 of an attachment via streaming read.

    Args:
        attachment: pypff attachment object with `.read_buffer(size)` method.
        window_kb: Read window size in KB (default 64 KB).

    Returns:
        Hex digest of SHA-256.
    """
    hasher = hashlib.sha256()
    window_bytes = window_kb * 1024

    while True:
        chunk = attachment.read_buffer(window_bytes)
        if not chunk:
            break
        hasher.update(chunk)

    return hasher.hexdigest()


def _parse_attachment(attachment) -> Attachment:
    """Parse a pypff attachment into an Attachment dataclass.

    The attachment object is consumed by the streaming hash read, so this must
    be called exactly once per attachment.
    """
    name = _safe_text(attachment, "name") or "<unnamed>"
    size = 0
    try:
        size = attachment.size
    except Exception:
        pass

    sha256_digest = _hash_attachment_streaming(attachment)

    return Attachment(name=name, size=size, sha256=sha256_digest)


def _parse_message(folder_path: tuple[str, ...], msg: PstMessage) -> EmailMessage:
    """Parse a pypff message into an EmailMessage dataclass."""
    folder = "/".join(folder_path)

    attachments: list[Attachment] = []
    try:
        count = msg.number_of_attachments
        for i in range(count):
            att = msg.get_attachment(i)
            attachments.append(_parse_attachment(att))
    except Exception:
        # Attachment enumeration failed — emit the message with zero attachments
        # rather than discarding the entire message.
        pass

    # Normalize PST timestamps to UTC-aware (pypff returns naive datetimes)
    import pytz

    submit_time = msg.client_submit_time
    delivery_time = msg.delivery_time
    if submit_time and submit_time.tzinfo is None:
        submit_time = submit_time.replace(tzinfo=pytz.utc)
    if delivery_time and delivery_time.tzinfo is None:
        delivery_time = delivery_time.replace(tzinfo=pytz.utc)

    return EmailMessage(
        folder=folder,
        submit_time=submit_time,
        delivery_time=delivery_time,
        sender_name=_safe_text(msg, "sender_name"),
        sender_email=_safe_text(msg, "sender_email_address"),
        subject=_safe_text(msg, "subject"),
        transport_headers=_safe_text(msg, "transport_headers")[:4000],
        body_preview=(
            _safe_text(msg, "plain_text_body") or _safe_text(msg, "html_body")
        )[:2000],
        attachments=tuple(attachments),
    )


class PstParser:
    """Parse PST files into frozen EmailMessage dataclasses.

    Usage:
        parser = PstParser()
        messages = parser.parse_file(Path("outlook.pst"))
    """

    def parse_file(self, path: Path) -> list[EmailMessage]:
        """Parse a PST file and return all messages as frozen dataclasses.

        Args:
            path: Path to the .pst file.

        Returns:
            List of EmailMessage objects in folder-walk order.

        Raises:
            FileNotFoundError: If the PST file does not exist.
            RuntimeError: If pypff fails to open the file.
        """
        if not path.exists():
            raise FileNotFoundError(f"PST file not found: {path}")

        pypff = _require_pypff()
        pst = pypff.file()
        pst.open(str(path))
        try:
            root = pst.get_root_folder()
            pairs = _walk_folder(root, tuple())
            messages = [_parse_message(folder_path, msg) for folder_path, msg in pairs]
            return messages
        finally:
            pst.close()
