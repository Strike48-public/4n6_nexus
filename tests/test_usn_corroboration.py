"""Tests for USN journal timestamp corroboration of timestomping.

Idea #16: parse a USN journal and escalate a single-artifact $SI<$FN
timestomp signal to a finding ONLY when the monotonic USN sequence
contradicts the file's claimed $SI timestamp ordering (ordering inversion).

Every behavior below is paired with an inverse/negative control.
"""

from __future__ import annotations

from sift_find_evil.findings import FindingCategory
from sift_find_evil.parsers.usn_parser import UsnRecord, parse_usn
from sift_find_evil.detectors.usn_timestomp_corroborator import corroborate_timestomp


def test_parse_usn_sorts_by_usn_ascending() -> None:
    # Arrange - records intentionally out of order
    raw = [
        {
            "usn": 500,
            "file_name": "evil.exe",
            "timestamp": "2024-06-01T12:05:00",
            "reason": "DATA_OVERWRITE",
        },
        {
            "usn": 100,
            "file_name": "a.log",
            "timestamp": "2024-01-01T00:00:00",
            "reason": "FILE_CREATE",
        },
        {
            "usn": 300,
            "file_name": "b.log",
            "timestamp": "2024-03-01T00:00:00",
            "reason": "CLOSE",
        },
    ]

    # Act
    parsed = parse_usn(raw)

    # Assert
    assert [r.usn for r in parsed] == [100, 300, 500]
    assert all(isinstance(r, UsnRecord) for r in parsed)
    assert parsed[0].file_name == "a.log"
    assert parsed[-1].reason == "DATA_OVERWRITE"


def test_parse_usn_empty_returns_empty() -> None:
    # Inverse control: no records in -> no records out
    assert parse_usn([]) == []


def test_backdated_si_with_usn_ordering_inversion_emits_finding() -> None:
    # Arrange - classic backdating: si_time pushed far into the past
    mft = {
        "file_name": "evil.exe",
        "si_time": "2020-01-01T00:00:00",
        "fn_time": "2024-06-01T12:00:00",
    }
    # Journal: evil.exe is the LAST real event (usn 500), yet a benign file
    # with a LOWER usn (earlier real event) has a real timestamp LATER than
    # evil.exe's claimed si_time -> ordering inversion.
    usn = parse_usn(
        [
            {
                "usn": 400,
                "file_name": "normal.log",
                "timestamp": "2024-03-01T00:00:00",
                "reason": "CLOSE",
            },
            {
                "usn": 500,
                "file_name": "evil.exe",
                "timestamp": "2024-06-01T12:05:00",
                "reason": "DATA_OVERWRITE",
            },
        ]
    )

    # Act
    finding = corroborate_timestomp(mft, usn)

    # Assert
    assert finding is not None
    assert finding.category == FindingCategory.TIMELINE_TAMPERING
    assert finding.severity == "high"
    assert finding.evidence.get("mitre_technique") == "T1070.006"
    assert "evil.exe" in finding.title
    assert finding.reasoning_chain  # non-empty rationale


def test_clean_file_not_backdated_returns_none() -> None:
    # Inverse control: si_time >= fn_time, no timestomp signal at all
    mft = {
        "file_name": "report.docx",
        "si_time": "2024-06-01T12:00:00",
        "fn_time": "2024-05-01T00:00:00",
    }
    usn = parse_usn(
        [
            {
                "usn": 400,
                "file_name": "report.docx",
                "timestamp": "2024-06-01T12:05:00",
                "reason": "CLOSE",
            },
        ]
    )

    assert corroborate_timestomp(mft, usn) is None


def test_backdated_but_usn_ordering_consistent_returns_none() -> None:
    # Sophisticated/laundered: si<fn (single-artifact suspicion) but the USN
    # sequence AGREES with the timestamps -> not enough to escalate.
    mft = {
        "file_name": "evil.exe",
        "si_time": "2024-06-01T12:00:00",
        "fn_time": "2024-06-02T12:00:00",
    }
    usn = parse_usn(
        [
            {
                "usn": 400,
                "file_name": "normal.log",
                "timestamp": "2024-05-01T00:00:00",
                "reason": "CLOSE",
            },
            {
                "usn": 500,
                "file_name": "evil.exe",
                "timestamp": "2024-06-02T12:05:00",
                "reason": "DATA_OVERWRITE",
            },
        ]
    )

    assert corroborate_timestomp(mft, usn) is None


def test_empty_usn_returns_none_even_when_backdated() -> None:
    # Inverse control: no journal corroboration available -> cannot escalate
    mft = {
        "file_name": "evil.exe",
        "si_time": "2020-01-01T00:00:00",
        "fn_time": "2024-06-01T12:00:00",
    }
    assert corroborate_timestomp(mft, []) is None


def test_backdated_but_no_target_event_in_journal_returns_none() -> None:
    # Arrange - $SI < $FN (suspicion) and the journal is non-empty, but it
    # contains NO record for the suspected file itself, so there is no real
    # event to anchor the ordering-inversion check against.
    mft = {
        "file_name": "evil.exe",
        "si_time": "2020-01-01T00:00:00",
        "fn_time": "2024-06-01T12:00:00",
    }
    usn = parse_usn(
        [
            {
                "usn": 400,
                "file_name": "normal.log",
                "timestamp": "2024-03-01T00:00:00",
                "reason": "CLOSE",
            },
        ]
    )

    # Act / Assert - no target event -> cannot escalate (corroborator line 66)
    assert corroborate_timestomp(mft, usn) is None


def test_benign_record_with_empty_timestamp_is_skipped_returns_none() -> None:
    # Arrange - the only OTHER-file record that has a lower USN than the
    # target has an EMPTY timestamp, so it cannot prove an inversion and must
    # be skipped. With no other candidate, no finding is produced.
    mft = {
        "file_name": "evil.exe",
        "si_time": "2020-01-01T00:00:00",
        "fn_time": "2024-06-01T12:00:00",
    }
    usn = parse_usn(
        [
            {
                "usn": 400,
                "file_name": "normal.log",
                "reason": "CLOSE",  # timestamp absent -> "" after parse
            },
            {
                "usn": 500,
                "file_name": "evil.exe",
                "timestamp": "2024-06-01T12:05:00",
                "reason": "DATA_OVERWRITE",
            },
        ]
    )

    # Act / Assert - empty-timestamp benign record skipped (corroborator 102)
    assert corroborate_timestomp(mft, usn) is None


def test_benign_record_at_or_after_target_usn_is_skipped_returns_none() -> None:
    # Arrange - the only OTHER-file record has a HIGHER usn than the target's
    # own event (i.e. it is not "earlier" in the journal), so it cannot prove
    # an inversion and is skipped. No finding is produced.
    mft = {
        "file_name": "evil.exe",
        "si_time": "2020-01-01T00:00:00",
        "fn_time": "2024-06-01T12:00:00",
    }
    usn = parse_usn(
        [
            {
                "usn": 500,
                "file_name": "evil.exe",
                "timestamp": "2024-06-01T12:05:00",
                "reason": "DATA_OVERWRITE",
            },
            {
                "usn": 600,  # higher than target's usn 500 -> not earlier
                "file_name": "normal.log",
                "timestamp": "2024-03-01T00:00:00",
                "reason": "CLOSE",
            },
        ]
    )

    # Act / Assert - later-USN benign record skipped (corroborator line 105)
    assert corroborate_timestomp(mft, usn) is None
