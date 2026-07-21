"""W32Time / NTP clock-offset recovery from System.evtx events.

Windows Time-Service (W32Time) writes the measured discrepancy between the
local clock and its NTP peer to the System event log. Recovering that offset
lets an examiner correct artifact timestamps back to true wall-clock time,
which matters when a host's clock has drifted or been tampered with.

Two event IDs carry the offset:

* Event ID 35 (Time-Service): the offset is embedded in the message text in
  raw 100-ns units, so ``offset_s = raw / 1e7``.
* Event ID 260 (Phase Offset): the offset is reported directly in seconds and
  is PREFERRED over EID 35 when both are present, because it is the refined
  phase measurement rather than the coarse initial sync value.

This module only reads pre-parsed event dicts (synthetic fixtures or real
EvtxECmd output); it never mutates its inputs.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

# Event IDs of interest and the "prefer 260 over 35" ordering.
_EID_TIME_SERVICE = 35
_EID_PHASE_OFFSET = 260
_VALID_EIDS = frozenset({_EID_TIME_SERVICE, _EID_PHASE_OFFSET})

# EID 35: "...from <peer>,0x9 offset <raw>." Raw value is in 100-ns units.
_EID35_PEER_RE = re.compile(r"from\s+([^\s,]+)")
_EID35_OFFSET_RE = re.compile(r"offset\s+(-?\d+(?:\.\d+)?)")

# EID 260: "Phase Offset: <float>s" already in seconds.
_EID260_OFFSET_RE = re.compile(r"Phase\s+Offset:\s*(-?\d+(?:\.\d+)?)\s*s")

# Raw 100-ns units per second.
_HUNDRED_NS_PER_SECOND = 1e7


@dataclass(frozen=True)
class ClockOffsetContext:
    """A recovered host-clock offset from a single W32Time event.

    Attributes:
        ntp_peer: The NTP peer name, or None (EID 260 does not carry a peer).
        offset_s: Measured clock offset in seconds (local minus true time).
        source_eid: The originating event ID (35 or 260).
        event_ts: ISO-8601 timestamp when the event was created.
    """

    ntp_peer: str | None
    offset_s: float
    source_eid: int
    event_ts: str


def _parse_eid35(message: str) -> tuple[str | None, float] | None:
    """Extract (peer, offset_s) from an EID 35 message, or None if malformed.

    Args:
        message: The event message text.

    Returns:
        A ``(peer, offset_s)`` tuple with the raw 100-ns offset converted to
        seconds, or None when no finite numeric offset is present.
    """
    offset_match = _EID35_OFFSET_RE.search(message)
    if offset_match is None:
        return None
    raw = float(offset_match.group(1))
    if not math.isfinite(raw):
        return None
    peer_match = _EID35_PEER_RE.search(message)
    peer = peer_match.group(1) if peer_match else None
    return peer, raw / _HUNDRED_NS_PER_SECOND


def _parse_eid260(message: str) -> float | None:
    """Extract the seconds offset from an EID 260 message, or None if malformed.

    Args:
        message: The event message text.

    Returns:
        The offset in seconds, or None when no finite value is present.
    """
    match = _EID260_OFFSET_RE.search(message)
    if match is None:
        return None
    value = float(match.group(1))
    if not math.isfinite(value):
        return None
    return value


def parse_clock_offsets(events: list[dict]) -> list[ClockOffsetContext]:
    """Recover host-clock offsets from W32Time System.evtx events.

    Filters to EID 35 and 260, extracts the offset (converting EID 35's raw
    100-ns units to seconds), and skips any event whose id is out of scope or
    whose offset is missing/non-finite. When both a 35 and a 260 context are
    recovered, only the preferred EID 260 contexts are returned.

    Args:
        events: Pre-parsed event dicts, each with keys ``event_id``,
            ``provider``, ``time_created``, and ``message``.

    Returns:
        A list of ClockOffsetContext, preferring EID 260 over EID 35 when both
        are present.
    """
    contexts: list[ClockOffsetContext] = []
    for event in events:
        event_id = event.get("event_id")
        if event_id not in _VALID_EIDS:
            continue
        message = event.get("message", "")
        event_ts = event.get("time_created", "")

        if event_id == _EID_TIME_SERVICE:
            parsed = _parse_eid35(message)
            if parsed is None:
                continue
            peer, offset_s = parsed
            contexts.append(
                ClockOffsetContext(
                    ntp_peer=peer,
                    offset_s=offset_s,
                    source_eid=_EID_TIME_SERVICE,
                    event_ts=event_ts,
                )
            )
        else:  # _EID_PHASE_OFFSET
            offset_s = _parse_eid260(message)
            if offset_s is None:
                continue
            contexts.append(
                ClockOffsetContext(
                    ntp_peer=None,
                    offset_s=offset_s,
                    source_eid=_EID_PHASE_OFFSET,
                    event_ts=event_ts,
                )
            )

    preferred = [c for c in contexts if c.source_eid == _EID_PHASE_OFFSET]
    return preferred if preferred else contexts


def corrected_time(observed_iso: str, offset_s: float) -> str:
    """Correct an observed timestamp by subtracting the measured clock offset.

    A positive offset means the local clock was running ahead of true time, so
    the true time is earlier; the offset is subtracted from the observed value.

    Args:
        observed_iso: An ISO-8601 timestamp (a trailing ``Z`` is accepted).
        offset_s: The measured clock offset in seconds.

    Returns:
        The corrected ISO-8601 timestamp in UTC.
    """
    normalized = observed_iso.replace("Z", "+00:00")
    observed = datetime.fromisoformat(normalized)
    if observed.tzinfo is None:
        observed = observed.replace(tzinfo=timezone.utc)
    corrected = observed - timedelta(seconds=offset_s)
    return corrected.isoformat()
