"""Detect data exfiltration via file-to-email correlation.

A file saved to disk and then sent as an email attachment within a short time
window (default: 300 seconds) is a strong indicator of intentional data
exfiltration. This detector correlates on-disk file hashes (SHA-256) with email
attachment hashes from PST files, then checks temporal proximity between file
modification and email send time.

This detector is artifact-centric: it does not look for specific file names,
user names, or case-specific indicators. It purely correlates cryptographic
hashes and timestamps across MFT and PST artifacts.
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from ..findings.categories import FindingCategory
from ..parsers.mft_parser import MFTEntry
from ..parsers.pst_parser import EmailMessage
from ..parsers.image_content_reader import ImageContentReader

logger = logging.getLogger(__name__)

# Time window for correlation: file modified → email sent
DEFAULT_TIME_WINDOW_SECONDS = 300

# Graduated confidence thresholds based on time delta
def _calculate_confidence(time_delta_seconds: float) -> tuple[float, str]:
    """Calculate confidence score based on time delta.

    Args:
        time_delta_seconds: Time between file modification and email send

    Returns:
        Tuple of (confidence_score, confidence_label)
    """
    if time_delta_seconds <= 60:
        return (0.95, "Very High")  # Immediate exfiltration
    elif time_delta_seconds <= 180:
        return (0.90, "High")  # Deliberate but not immediate
    else:
        return (0.85, "Medium-High")  # Could be manual or automated


@dataclass(frozen=True)
class ExfilMatch:
    """A single file-to-email correlation match."""

    file_path: str
    file_size: int
    file_modified: datetime
    file_sha256: str
    email_subject: str
    email_sent: datetime
    email_sender: str
    attachment_name: str
    attachment_size: int
    time_delta_seconds: float
    is_primary: bool = False  # Shortest delta = primary evidence

    def to_dict(self) -> dict[str, Any]:
        return {
            "file_path": self.file_path,
            "file_size": self.file_size,
            "file_modified": self.file_modified.isoformat() if self.file_modified else None,
            "file_sha256": self.file_sha256,
            "email_subject": self.email_subject,
            "email_sent": self.email_sent.isoformat() if self.email_sent else None,
            "email_sender": self.email_sender,
            "attachment_name": self.attachment_name,
            "attachment_size": self.attachment_size,
            "time_delta_seconds": round(self.time_delta_seconds, 1),
            "is_primary": self.is_primary,
        }


@dataclass(frozen=True)
class ExfilFinding:
    """A finding that mirrors the engine Finding shape for CLI rendering."""

    title: str
    description: str
    finding_type: str
    severity: str
    confidence: float
    confidence_label: str
    category: FindingCategory
    matches: list[ExfilMatch] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)
    reasoning_chain: list[str] = field(default_factory=list)
    contradictions: list[Any] = field(default_factory=list)
    resolutions: list[Any] = field(default_factory=list)
    confidence_calculation: dict[str, Any] = field(default_factory=dict)
    artifact_sources: list[str] = field(default_factory=list)
    detected_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict:
        return {
            "title": self.title,
            "description": self.description,
            "type": self.finding_type,
            "severity": self.severity,
            "category": self.category.value,
            "evidence": self.evidence,
            "confidence": round(self.confidence, 2),
            "confidence_label": self.confidence_label,
            "reasoning_chain": self.reasoning_chain,
            "contradictions": self.contradictions,
            "resolutions": self.resolutions,
            "confidence_calculation": self.confidence_calculation,
            "detected_at": self.detected_at.isoformat(),
            "artifact_sources": self.artifact_sources,
        }


def _compute_file_hash(reader: ImageContentReader, entry: MFTEntry) -> str | None:
    """Compute SHA-256 hash of a file from disk image.

    Args:
        reader: ImageContentReader for accessing file content
        entry: MFT entry pointing to the file

    Returns:
        SHA-256 hex digest, or None if file cannot be read
    """
    try:
        content = reader.read_file(entry)
        return hashlib.sha256(content).hexdigest()
    except Exception as e:
        logger.warning(f"Cannot hash {entry.file_path}: {e}")
        return None


def _filter_mft_by_email_timeframe(
    mft_entries: list[MFTEntry],
    emails: list[EmailMessage],
    buffer_days: int = 1,
) -> list[MFTEntry]:
    """Filter MFT entries to only files modified near email activity.

    This dramatically reduces the number of files we need to hash. For example,
    if emails span 2009-12-11 only, we only hash files modified 2009-12-10 to
    2009-12-12 (±1 day buffer).

    Args:
        mft_entries: All MFT entries from disk
        emails: All email messages from PST
        buffer_days: Days before/after email activity to include

    Returns:
        Filtered list of MFT entries
    """
    if not emails:
        return []

    # Get email date range
    email_dates = [
        email.submit_time or email.delivery_time
        for email in emails
        if email.submit_time or email.delivery_time
    ]

    if not email_dates:
        logger.warning("No emails with timestamps found, cannot filter MFT by timeframe")
        return []

    earliest = min(email_dates) - timedelta(days=buffer_days)
    latest = max(email_dates) + timedelta(days=buffer_days)

    logger.info(f"Filtering MFT to files modified {earliest} to {latest}")

    # Filter MFT entries
    candidates = []
    for entry in mft_entries:
        # Prefer $FILE_NAME modified time (more reliable)
        mod_time = entry.get_modification_time(prefer_fn=True)
        if mod_time and earliest <= mod_time <= latest:
            candidates.append(entry)

    logger.info(f"Filtered {len(mft_entries)} MFT entries → {len(candidates)} candidates")
    return candidates


def _correlate_hashes(
    file_hashes: dict[str, tuple[MFTEntry, str]],
    emails: list[EmailMessage],
    time_window_seconds: int,
) -> list[ExfilMatch]:
    """Correlate file hashes with email attachment hashes.

    Args:
        file_hashes: Dict of {sha256: (mft_entry, hash)} for all hashed files
        emails: All email messages with attachments
        time_window_seconds: Max time delta for correlation

    Returns:
        List of correlation matches
    """
    matches = []

    for email in emails:
        if not email.attachments:
            continue

        email_time = email.submit_time or email.delivery_time
        if not email_time:
            continue

        for attachment in email.attachments:
            if attachment.sha256 not in file_hashes:
                continue

            # Found a hash match
            mft_entry, _ = file_hashes[attachment.sha256]
            file_time = mft_entry.get_modification_time(prefer_fn=True)

            if not file_time:
                continue

            # Check temporal proximity
            time_delta = (email_time - file_time).total_seconds()

            if 0 <= time_delta <= time_window_seconds:
                match = ExfilMatch(
                    file_path=mft_entry.file_path,
                    file_size=mft_entry.file_size,
                    file_modified=file_time,
                    file_sha256=attachment.sha256,
                    email_subject=email.subject,
                    email_sent=email_time,
                    email_sender=email.sender_email,
                    attachment_name=attachment.name,
                    attachment_size=attachment.size,
                    time_delta_seconds=time_delta,
                )
                matches.append(match)
                logger.info(
                    f"Correlation match: {mft_entry.file_path} → "
                    f"{email.subject} (Δ={time_delta:.1f}s)"
                )

    return matches


def _build_reasoning(matches: list[ExfilMatch], stats: dict[str, int]) -> list[str]:
    """Build reasoning chain for exfiltration finding."""
    steps = []

    steps.append(
        f"Scanned {stats['total_mft_entries']} MFT entries, "
        f"filtered to {stats['candidates']} files modified near email activity"
    )

    steps.append(
        f"Hashed {stats['hashed']} files "
        f"(skipped {stats['skipped']} due to read errors)"
    )

    steps.append(
        f"Scanned {stats['total_emails']} emails with "
        f"{stats['total_attachments']} attachments"
    )

    steps.append(
        f"Found {len(matches)} file-to-email correlation(s) within "
        f"{DEFAULT_TIME_WINDOW_SECONDS}s time window"
    )

    # Detail each match
    for i, match in enumerate(matches, 1):
        primary = " (PRIMARY)" if match.is_primary else ""
        steps.append(
            f"  Match {i}{primary}: {match.file_path} "
            f"({match.file_size:,} bytes, SHA-256: {match.file_sha256[:16]}...) "
            f"saved at {match.file_modified.strftime('%Y-%m-%d %H:%M:%S')}, "
            f"emailed {match.time_delta_seconds:.1f}s later "
            f"as '{match.attachment_name}' in email '{match.email_subject}'"
        )

    steps.append(
        "File-to-email correlation with temporal proximity (<300s) is a strong "
        "indicator of intentional data exfiltration"
    )

    return steps


def _build_evidence(matches: list[ExfilMatch], stats: dict[str, int]) -> dict[str, Any]:
    """Build evidence dict for exfiltration finding."""
    return {
        "total_mft_entries": stats["total_mft_entries"],
        "filtered_candidates": stats["candidates"],
        "files_hashed": stats["hashed"],
        "files_skipped": stats["skipped"],
        "total_emails": stats["total_emails"],
        "total_attachments": stats["total_attachments"],
        "matches_found": len(matches),
        "time_window_seconds": DEFAULT_TIME_WINDOW_SECONDS,
        "correlations": [match.to_dict() for match in matches],
    }


def detect_exfiltration(
    image_path: Path,
    mft_entries: list[MFTEntry],
    emails: list[EmailMessage],
    *,
    time_window_seconds: int = DEFAULT_TIME_WINDOW_SECONDS,
) -> ExfilFinding | None:
    """Detect data exfiltration via file-to-email correlation.

    Args:
        image_path: Path to disk image (E01, raw, etc.)
        mft_entries: All MFT entries from disk
        emails: All email messages from PST file
        time_window_seconds: Max time delta for correlation (default: 300s)

    Returns:
        ExfilFinding if correlations found, else None
    """
    stats = {
        "total_mft_entries": len(mft_entries),
        "candidates": 0,
        "hashed": 0,
        "skipped": 0,
        "total_emails": len(emails),
        "total_attachments": sum(len(e.attachments) for e in emails),
    }

    logger.info(
        f"Starting exfiltration detection: {stats['total_mft_entries']} MFT entries, "
        f"{stats['total_emails']} emails with {stats['total_attachments']} attachments"
    )

    # Step 1: Filter MFT entries by email timeframe
    candidates = _filter_mft_by_email_timeframe(mft_entries, emails)
    stats["candidates"] = len(candidates)

    if not candidates:
        logger.info("No MFT entries in email timeframe, skipping exfiltration detection")
        return None

    # Step 2: Hash candidate files
    file_hashes: dict[str, tuple[MFTEntry, str]] = {}

    with ImageContentReader(image_path) as reader:
        for entry in candidates:
            file_hash = _compute_file_hash(reader, entry)
            if file_hash:
                file_hashes[file_hash] = (entry, file_hash)
                stats["hashed"] += 1
            else:
                stats["skipped"] += 1

    logger.info(f"Hashed {stats['hashed']} files, skipped {stats['skipped']}")

    if not file_hashes:
        logger.warning("No files successfully hashed, cannot detect exfiltration")
        return None

    # Step 3: Correlate hashes with email attachments
    matches = _correlate_hashes(file_hashes, emails, time_window_seconds)

    if not matches:
        logger.info("No file-to-email correlations found")
        return None

    # Step 4: Mark primary evidence (shortest time delta)
    matches.sort(key=lambda m: m.time_delta_seconds)
    primary_match = ExfilMatch(
        **{**matches[0].__dict__, "is_primary": True}
    )
    matches[0] = primary_match

    # Step 5: Build finding
    reasoning = _build_reasoning(matches, stats)
    evidence = _build_evidence(matches, stats)

    # Calculate confidence based on primary match time delta
    confidence, confidence_label = _calculate_confidence(primary_match.time_delta_seconds)

    return ExfilFinding(
        title=f"Data exfiltration detected: {len(matches)} file(s) emailed within {time_window_seconds}s",
        description=(
            f"File {primary_match.file_path} ({primary_match.file_size:,} bytes) "
            f"was saved to disk and then sent as an email attachment "
            f"{primary_match.time_delta_seconds:.1f} seconds later. "
            f"SHA-256 hash correlation confirms file content matches attachment. "
            f"Temporal proximity indicates intentional exfiltration."
        ),
        finding_type="indicator",
        severity="critical",
        confidence=confidence,
        confidence_label=confidence_label,
        category=FindingCategory.DATA_EXFILTRATION,
        matches=matches,
        evidence=evidence,
        reasoning_chain=reasoning,
        artifact_sources=["mft", "pst", "disk_image"],
        confidence_calculation={
            "base": confidence,
            "time_delta_seconds": primary_match.time_delta_seconds,
            "rationale": (
                f"SHA-256 hash match + temporal proximity ({primary_match.time_delta_seconds:.1f}s) "
                f"indicates intentional exfiltration. Confidence graduated by time delta: "
                f"0-60s=0.95, 60-180s=0.90, 180-300s=0.85."
            ),
        },
    )
