"""USN change journal parser.

Parses pre-extracted NTFS USN ($UsnJrnl:$J) change-journal records into a
sorted, typed sequence. The USN journal is an append-only, monotonically
increasing log: a higher USN always corresponds to a later real filesystem
event. That monotonic property is what lets a downstream detector corroborate
or refute a suspected $SI timestamp manipulation (see
``detectors/usn_timestomp_corroborator``).

Input is synthetic/in-memory dicts mirroring the shape a tool such as
``MFTECmd`` / ``fls`` would emit; no real evidence is read here.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class UsnRecord:
    """A single USN change-journal entry.

    Attributes:
        usn: Update Sequence Number - monotonic offset into the journal.
        file_name: Name of the file the entry refers to.
        timestamp: ISO-8601 timestamp string of the recorded event.
        reason: USN reason code (e.g. ``DATA_OVERWRITE``, ``FILE_CREATE``).
    """

    usn: int
    file_name: str
    timestamp: str
    reason: str


def parse_usn(records: list[dict]) -> list[UsnRecord]:
    """Parse raw USN journal dicts into typed records sorted by USN ascending.

    Args:
        records: Raw journal entries. Each must provide ``usn`` and
            ``file_name``; ``timestamp`` and ``reason`` default to empty
            strings when absent.

    Returns:
        A new list of ``UsnRecord`` sorted by ``usn`` ascending. The input
        list is never mutated.
    """
    parsed = [
        UsnRecord(
            usn=int(record["usn"]),
            file_name=str(record["file_name"]),
            timestamp=str(record.get("timestamp", "")),
            reason=str(record.get("reason", "")),
        )
        for record in records
    ]
    return sorted(parsed, key=lambda entry: entry.usn)
