"""Tests for W32Time / NTP clock-offset recovery (Event IDs 35 and 260).

Validates parse_clock_offsets and corrected_time using inline synthetic
System.evtx-style event dicts. Every positive case is paired with an
inverse/negative control per project TDD conventions.
"""

from __future__ import annotations

import math

from sift_find_evil.parsers.timesync import (
    ClockOffsetContext,
    corrected_time,
    parse_clock_offsets,
)


def test_eid35_yields_peer_and_converted_offset() -> None:
    # Arrange: EID 35 raw offset is in 100-ns units (5_000_000 => 0.5 s).
    events = [
        {
            "event_id": 35,
            "provider": "Microsoft-Windows-Time-Service",
            "time_created": "2026-07-20T12:00:00Z",
            "message": (
                "The time provider NtpClient is currently receiving valid "
                "time data from time.windows.com,0x9 offset 5000000."
            ),
        }
    ]

    # Act
    contexts = parse_clock_offsets(events)

    # Assert
    assert len(contexts) == 1
    ctx = contexts[0]
    assert isinstance(ctx, ClockOffsetContext)
    assert ctx.ntp_peer == "time.windows.com"
    assert math.isclose(ctx.offset_s, 0.5, rel_tol=1e-9)
    assert ctx.source_eid == 35
    assert ctx.event_ts == "2026-07-20T12:00:00Z"


def test_eid260_yields_seconds_offset() -> None:
    # Arrange: EID 260 offset is already in seconds.
    events = [
        {
            "event_id": 260,
            "provider": "Microsoft-Windows-Time-Service",
            "time_created": "2026-07-20T12:05:00Z",
            "message": "Phase Offset: -1.2500000s Root Delay: 0.03s",
        }
    ]

    # Act
    contexts = parse_clock_offsets(events)

    # Assert
    assert len(contexts) == 1
    ctx = contexts[0]
    assert math.isclose(ctx.offset_s, -1.25, rel_tol=1e-9)
    assert ctx.source_eid == 260


def test_eid260_preferred_over_eid35_for_same_window() -> None:
    # Arrange: both present; EID 260 must win.
    events = [
        {
            "event_id": 35,
            "provider": "Microsoft-Windows-Time-Service",
            "time_created": "2026-07-20T12:00:00Z",
            "message": "receiving valid time data from time.nist.gov,0x9 offset 9990000.",
        },
        {
            "event_id": 260,
            "provider": "Microsoft-Windows-Time-Service",
            "time_created": "2026-07-20T12:00:01Z",
            "message": "Phase Offset: 0.7500000s",
        },
    ]

    # Act
    contexts = parse_clock_offsets(events)

    # Assert: only the preferred EID 260 context is returned.
    assert len(contexts) == 1
    assert contexts[0].source_eid == 260
    assert math.isclose(contexts[0].offset_s, 0.75, rel_tol=1e-9)


def test_non_time_event_is_skipped() -> None:
    # Arrange (inverse/negative control): unrelated event id.
    events = [
        {
            "event_id": 4624,
            "provider": "Microsoft-Windows-Security-Auditing",
            "time_created": "2026-07-20T12:00:00Z",
            "message": "An account was successfully logged on. offset 5000000.",
        }
    ]

    # Act
    contexts = parse_clock_offsets(events)

    # Assert
    assert contexts == []


def test_malformed_offset_is_skipped() -> None:
    # Arrange (negative control): EID 35 with no parseable numeric offset.
    events = [
        {
            "event_id": 35,
            "provider": "Microsoft-Windows-Time-Service",
            "time_created": "2026-07-20T12:00:00Z",
            "message": "receiving valid time data from time.windows.com,0x9 offset NaN-ish.",
        }
    ]

    # Act
    contexts = parse_clock_offsets(events)

    # Assert
    assert contexts == []


def test_corrected_time_subtracts_offset() -> None:
    # Arrange: observed clock is 0.5 s fast, so true time is earlier.
    observed = "2026-07-20T12:00:00Z"

    # Act
    corrected = corrected_time(observed, 0.5)

    # Assert
    assert corrected == "2026-07-20T11:59:59.500000+00:00"


def test_corrected_time_negative_offset_shifts_forward() -> None:
    # Arrange (inverse control): negative offset moves time forward.
    observed = "2026-07-20T12:00:00Z"

    # Act
    corrected = corrected_time(observed, -2.0)

    # Assert
    assert corrected == "2026-07-20T12:00:02+00:00"


# A digit run long enough to overflow float() to +inf without an exponent.
_NON_FINITE_DIGITS = "9" * 400


def test_eid35_non_finite_offset_is_skipped() -> None:
    # Negative control: EID 35 offset that overflows float() to inf is dropped.
    events = [
        {
            "event_id": 35,
            "provider": "Microsoft-Windows-Time-Service",
            "time_created": "2026-07-20T12:00:00Z",
            "message": f"time data from time.windows.com,0x9 offset {_NON_FINITE_DIGITS}.",
        }
    ]

    assert parse_clock_offsets(events) == []


def test_eid260_missing_offset_is_skipped() -> None:
    # Negative control: EID 260 with no "Phase Offset:" token yields nothing.
    events = [
        {
            "event_id": 260,
            "provider": "Microsoft-Windows-Time-Service",
            "time_created": "2026-07-20T12:00:00Z",
            "message": "Root Delay: 0.03s (no phase offset present)",
        }
    ]

    assert parse_clock_offsets(events) == []


def test_eid260_non_finite_offset_is_skipped() -> None:
    # Negative control: EID 260 offset that overflows float() to inf is dropped.
    events = [
        {
            "event_id": 260,
            "provider": "Microsoft-Windows-Time-Service",
            "time_created": "2026-07-20T12:00:00Z",
            "message": f"Phase Offset: {_NON_FINITE_DIGITS}s",
        }
    ]

    assert parse_clock_offsets(events) == []


def test_corrected_time_naive_timestamp_is_treated_as_utc() -> None:
    # A timestamp with no timezone is assumed UTC before correcting.
    observed = "2026-07-20T12:00:00"

    corrected = corrected_time(observed, 0.5)

    assert corrected == "2026-07-20T11:59:59.500000+00:00"
