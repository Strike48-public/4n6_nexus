"""Corroborate a suspected $SI timestomp against the USN change journal.

A single $SI < $FN delta is only *suspicion* - $SI times are trivially
forgeable and legitimate archive/copy operations can produce the same shape.
This detector escalates that suspicion to a finding ONLY when the USN journal,
which is append-only and monotonic, contradicts the file's claimed $SI
ordering.

The contradiction we look for is an *ordering inversion*: the suspected file's
own real USN event is later (higher USN) than a benign file's real USN event,
yet the suspected file claims a $SI time EARLIER than that benign file's real
event time. A monotonic journal cannot honestly produce that ordering, so the
earlier $SI time must have been backdated.

MITRE ATT&CK: T1070.006 (Indicator Removal: Timestomp).
"""

from __future__ import annotations

from datetime import datetime

from sift_find_evil.findings import Finding, FindingCategory


def _parse_iso(value: str) -> datetime:
    """Parse an ISO-8601 timestamp string into a datetime.

    Args:
        value: ISO-8601 timestamp string.

    Returns:
        The parsed ``datetime``.
    """
    return datetime.fromisoformat(value)


def corroborate_timestomp(mft_entry: dict, usn_records: list) -> Finding | None:
    """Escalate a $SI<$FN timestomp signal when the USN journal disagrees.

    Args:
        mft_entry: MFT record with ``file_name``, ``si_time`` and ``fn_time``
            (ISO-8601 strings).
        usn_records: Parsed ``UsnRecord`` sequence (any order); the journal is
            treated as monotonic by USN.

    Returns:
        A high-severity ``TIMELINE_TAMPERING`` ``Finding`` when the classic
        backdating shape ($SI < $FN) is confirmed by a USN ordering inversion;
        otherwise ``None``.
    """
    file_name = str(mft_entry["file_name"])
    si_time = _parse_iso(mft_entry["si_time"])
    fn_time = _parse_iso(mft_entry["fn_time"])

    # No single-artifact suspicion: not backdated -> nothing to corroborate.
    if si_time >= fn_time:
        return None

    # No journal corroboration available -> cannot escalate on one artifact.
    if not usn_records:
        return None

    # The suspected file's own real event (its highest USN in the journal).
    target_events = [r for r in usn_records if r.file_name == file_name]
    if not target_events:
        return None
    target_event = max(target_events, key=lambda r: r.usn)

    # Look for an ordering inversion against any OTHER file: a benign file with
    # a LOWER usn (earlier real event) whose real timestamp is nonetheless
    # LATER than the suspected file's claimed si_time. A monotonic journal
    # cannot honestly produce that unless the si_time was backdated.
    inversion = _find_ordering_inversion(file_name, si_time, target_event, usn_records)
    if inversion is None:
        return None

    return _build_finding(file_name, si_time, fn_time, target_event, inversion)


def _find_ordering_inversion(
    file_name: str,
    si_time: datetime,
    target_event,
    usn_records: list,
):
    """Return the first benign record proving an ordering inversion, or None.

    Args:
        file_name: Name of the suspected file.
        si_time: Claimed $SI time of the suspected file.
        target_event: The suspected file's own (highest-USN) journal record.
        usn_records: Full parsed journal sequence.

    Returns:
        The benign ``UsnRecord`` that contradicts the claimed ordering, or
        ``None`` if the journal is consistent with the timestamps.
    """
    for record in usn_records:
        if record.file_name == file_name:
            continue
        if not record.timestamp:
            continue
        # Benign event happened earlier in the journal (lower USN) ...
        if record.usn >= target_event.usn:
            continue
        # ... yet its real time is LATER than the suspected file's claimed
        # si_time -> the si_time is impossibly early -> backdated.
        if _parse_iso(record.timestamp) > si_time:
            return record
    return None


def _build_finding(
    file_name: str,
    si_time: datetime,
    fn_time: datetime,
    target_event,
    inversion,
) -> Finding:
    """Construct the timestomp corroboration finding.

    Args:
        file_name: Suspected file name.
        si_time: Claimed $SI time.
        fn_time: $FN time.
        target_event: Suspected file's own journal record.
        inversion: Benign record proving the ordering inversion.

    Returns:
        A fully populated ``Finding``.
    """
    reasoning = [
        f"$SI ({si_time.isoformat()}) precedes $FN ({fn_time.isoformat()}): "
        "classic backdating shape, single-artifact suspicion.",
        f"USN {target_event.usn} records the real event for {file_name} at "
        f"{target_event.timestamp}.",
        f"USN {inversion.usn} for {inversion.file_name} (a lower/earlier "
        f"journal position) occurred at {inversion.timestamp}, which is LATER "
        "than the claimed $SI time.",
        "A monotonic USN journal cannot produce this ordering honestly: the "
        "$SI time must have been backdated. Suspicion escalated.",
    ]
    return Finding(
        title=f"Timestomp corroborated by USN journal: {file_name}",
        description=(
            f"The $SI creation time of {file_name} was backdated to "
            f"{si_time.isoformat()}, but the USN change journal's monotonic "
            "ordering contradicts that claim."
        ),
        finding_type="indicator",
        severity="high",
        category=FindingCategory.TIMELINE_TAMPERING,
        evidence={
            "file_name": file_name,
            "si_time": si_time.isoformat(),
            "fn_time": fn_time.isoformat(),
            "target_usn": target_event.usn,
            "inversion_usn": inversion.usn,
            "inversion_file": inversion.file_name,
            "inversion_timestamp": inversion.timestamp,
            "mitre_technique": "T1070.006",
        },
        confidence=0.9,
        confidence_label="High",
        reasoning_chain=reasoning,
        artifact_sources=["$MFT", "$UsnJrnl:$J"],
    )
