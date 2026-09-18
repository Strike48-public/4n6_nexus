"""Adapt parsed EVTX entries into flat Sigma-event dicts (SFE-katy PR2).

The mini-Sigma matcher (:mod:`.matcher`) evaluates rules over flat
``{field: value}`` maps keyed by Sigma logical field names (``Image``,
``CommandLine``, ``ParentImage``, ``TargetUserName``, ...). The EVTX parser emits
:class:`~sift_find_evil.parsers.evtx_parser.EventLogEntry` objects whose
Sigma-relevant fields live either in positional ``payload_dataN`` columns or in
``payload_json["EventData"]["Data"]`` (reachable via accessor methods). This
module is the bridge: one entry -> one flat Sigma event, with a per-EventID field
map for the event types our synthetic corpus actually contains (process creation
and logons).

Design notes:
- A field that resolves to ``None``/empty is OMITTED, never emitted as ``None``.
  The matcher tests ``field_name in event``, so a present-but-None field would
  falsely register as present and could make a ``not`` condition misfire.
- Common routing fields (EventID, Channel, Computer) are always present so a
  rule's logsource/EventID selector can match.
- Inputs are never mutated; process/command-line extraction reuses the parser's
  own accessors so the JSON-payload vs positional-column precedence stays in one
  place.
"""

from __future__ import annotations

from typing import Any, Dict

from sift_find_evil.parsers.evtx_parser import EventLogEntry

# Logon EventIDs whose account/type live in the positional payload columns.
_LOGON_EVENT_IDS = frozenset({4624, 4625, 4648})


def _clean(value: Any) -> str | None:
    """Return a trimmed non-empty string, or None for absent/blank input."""
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _logon_type(raw: Any) -> str | None:
    """Extract the numeric logon type from an EvtxECmd ``LogonType N`` payload.

    The 4624/4625 payload column is shaped like ``"LogonType 3"``; a Sigma rule
    wants the bare ``"3"`` so it can match ``LogonType: 3``. Falls back to the
    trimmed raw value when it is not in the expected shape.
    """
    text = _clean(raw)
    if text is None:
        return None
    token = text.split()[-1]
    return token or text


def _set(event: Dict[str, Any], key: str, value: Any) -> None:
    """Assign ``key`` only when ``value`` cleans to a non-empty string."""
    cleaned = _clean(value)
    if cleaned is not None:
        event[key] = cleaned


def event_to_sigma(entry: EventLogEntry) -> Dict[str, Any]:
    """Convert one :class:`EventLogEntry` into a flat Sigma-event dict.

    Args:
        entry: A parsed EVTX entry.

    Returns:
        A flat ``{field: value}`` dict keyed by Sigma logical field names.
        ``EventID`` is an int; all other values are non-empty strings. Fields
        that are absent on the entry are omitted (never ``None``).
    """
    event: Dict[str, Any] = {"EventID": entry.event_id}
    _set(event, "Channel", entry.channel)
    _set(event, "Computer", entry.computer)
    _set(event, "MapDescription", entry.map_description)

    if entry.is_process_creation():
        # 4688/592: Image + CommandLine via the parser's JSON-or-positional
        # accessors; ParentImage from the positional parent column (pd4).
        _set(event, "Image", entry.get_process_name())
        _set(event, "CommandLine", entry.get_command_line())
        _set(event, "ParentImage", entry.payload_data4)
    elif entry.event_id in _LOGON_EVENT_IDS:
        # 4624/4625/4648: target account (pd1, shaped "Target: DOMAIN\\user")
        # and logon type (pd2, shaped "LogonType N"); source host is a column.
        _set(event, "TargetUserName", entry.payload_data1)
        _set(event, "LogonType", _logon_type(entry.payload_data2))
        _set(event, "RemoteHost", entry.remote_host)

    return event
