"""Parser for legacy Windows `.Evt` event log files (Windows XP / 2003).

Windows XP predates EvtxECmd's native format. The binary record layout is
documented in MS-EVEN: each record begins with a 4-byte length, the `LfLe`
magic, then fixed fields (record number, times, event id, type, counts) and
offsets into the record body for the strings / data / sid regions.

This reader emits `EventLogEntry` objects that are indistinguishable from the
EvtxECmd CSV path downstream. Timestamps are UTC. Process creation events on
XP are Event ID 592 (not 4688); we map their argv[0] into `payload_data1`
(process path) and argv[1] into `payload_data6` (command line surrogate, often
absent on XP) so the self-correction engine can treat them identically.
"""

from __future__ import annotations

import struct
from datetime import datetime, timezone
from pathlib import Path

from .evtx_parser import EventLogEntry

EVT_FILE_MAGIC = b"LfLe"
EVT_HEADER_SIZE = 48

# Legacy "classic" process-creation event id (Windows XP / 2003 / NT).
# Vista and later emit 4688 in the Security channel.
XP_PROCESS_CREATION_EVENT_ID = 592

# Event levels in the legacy format are a 16-bit bitmask; the four levels we
# care about are EVENTLOG_*_TYPE values from Microsoft's winbase.h.
_EVT_TYPE_LEVEL = {
    0x0001: "Error",
    0x0002: "Warning",
    0x0004: "Information",
    0x0008: "Success",
    0x0010: "Failure",
}

# Any record whose payload strings we can not parse still produces an entry
# with event_id and time_created populated - we just skip the payload fields.


class EvtParser:
    """Read records out of a classic `.Evt` file."""

    def parse_file(
        self, path: str | Path, filter_event_ids: list[int] | None = None
    ) -> list[EventLogEntry]:
        """Parse a legacy .Evt file and extract event log entries.

        Reads the circular event log file format used on Windows XP / 2003,
        navigating the linked record chain without modifying evidence.

        Args:
            path: Path to the .Evt file.
            filter_event_ids: Optional list of event IDs to include (others are
                skipped). If None, all events are included.

        Returns:
            List of EventLogEntry objects extracted from the file.

        Raises:
            ValueError: If the file is not a valid .Evt file (bad magic or size).
        """
        data = Path(path).read_bytes()
        if len(data) < EVT_HEADER_SIZE or data[4:8] != EVT_FILE_MAGIC:
            raise ValueError(f"Not a classic .Evt file: {path}")

        start_off, end_off = struct.unpack_from("<II", data, 16)

        # Empty logs: header only, start == end == EVT_HEADER_SIZE. This is
        # common on XP Security logs when auditing was never enabled.
        if start_off >= end_off or start_off >= len(data):
            return []

        entries: list[EventLogEntry] = []
        off = start_off
        seen_offsets: set[int] = set()
        # Records may wrap around the end of the file in circular mode; we
        # stop on magic mismatch or when we revisit an offset.
        while off + 8 < len(data):
            if off in seen_offsets:
                break
            seen_offsets.add(off)

            (record_length,) = struct.unpack_from("<I", data, off)
            if record_length == 0 or record_length > len(data):
                break
            if data[off + 4 : off + 8] != EVT_FILE_MAGIC:
                break

            entry = self._parse_record(data, off, record_length)
            if entry is None:
                off += record_length
                continue

            if filter_event_ids is None or entry.event_id in filter_event_ids:
                entries.append(entry)

            off += record_length

        return entries

    def _parse_record(self, data: bytes, off: int, rec_len: int) -> EventLogEntry | None:
        try:
            (
                _rec_len,
                _magic,
                record_number,
                time_generated,
                _time_written,
                event_id_full,
                event_type,
                num_strings,
                _event_category,
                _reserved_flags,
                _closing_record_number,
                strings_offset,
                user_sid_len,
                user_sid_offset,
                _data_len,
                _data_offset,
            ) = struct.unpack_from("<I4sIIIIHHHHIIIIII", data, off)
        except struct.error:
            return None

        event_id = event_id_full & 0xFFFF

        source_name = self._read_cstr(data, off + 56)
        computer_name_off = off + 56 + (len(source_name) + 1) * 2
        computer = self._read_cstr(data, computer_name_off)

        user_id = self._read_user_sid(data, off, user_sid_offset, user_sid_len)

        strings = self._read_strings(data, off, strings_offset, num_strings, rec_len)

        level = _EVT_TYPE_LEVEL.get(event_type, f"Type{event_type}")

        payload1 = strings[0] if len(strings) >= 1 else None
        payload2 = strings[1] if len(strings) >= 2 else None
        payload3 = strings[2] if len(strings) >= 3 else None
        payload4 = strings[3] if len(strings) >= 4 else None
        payload5 = strings[4] if len(strings) >= 5 else None
        # argv[5] on XP 592 is the TokenElevationType/Authentication Id bucket;
        # XP does not emit a real command line, so payload_data6 is None.
        payload6 = strings[5] if len(strings) >= 6 else None

        # XP Event 592 strings layout (MS-EVEN / Security.Auditing.Process):
        #   [0] NewProcessId, [1] ImageFileName, [2] ...
        # We rewrite into the 4688-compatible shape so the engine's
        # `get_process_name()` works without caring about the OS version.
        if event_id == XP_PROCESS_CREATION_EVENT_ID and len(strings) >= 2:
            payload1 = strings[1]  # Image file name (process path)
            payload6 = None  # XP 592 does not include a command line

        time_created = _from_unix(time_generated)

        return EventLogEntry(
            time_created=time_created,
            event_id=event_id,
            record_id=record_number,
            computer=computer,
            channel=source_name,
            level=level,
            user_id=user_id,
            payload_data1=payload1,
            payload_data2=payload2,
            payload_data3=payload3,
            payload_data4=payload4,
            payload_data5=payload5,
            payload_data6=payload6,
            map_description=source_name,
        )

    @staticmethod
    def _read_cstr(data: bytes, off: int) -> str:
        j = off
        while j + 1 < len(data):
            if data[j] == 0 and data[j + 1] == 0:
                break
            j += 2
        return data[off:j].decode("utf-16-le", errors="replace")

    @staticmethod
    def _read_strings(
        data: bytes, rec_off: int, strings_off: int, num_strings: int, rec_len: int
    ) -> list[str]:
        if num_strings == 0 or strings_off == 0:
            return []
        cur = rec_off + strings_off
        rec_end = rec_off + rec_len
        out: list[str] = []
        for _ in range(num_strings):
            if cur >= rec_end or cur >= len(data):
                break
            j = cur
            while j + 1 < rec_end and j + 1 < len(data):
                if data[j] == 0 and data[j + 1] == 0:
                    break
                j += 2
            out.append(data[cur:j].decode("utf-16-le", errors="replace"))
            cur = j + 2
        return out

    @staticmethod
    def _read_user_sid(data: bytes, rec_off: int, sid_off: int, sid_len: int) -> str | None:
        if sid_len == 0 or sid_off == 0:
            return None
        start = rec_off + sid_off
        if start + sid_len > len(data):
            return None
        sid_bytes = data[start : start + sid_len]
        if len(sid_bytes) < 8:
            return None
        revision = sid_bytes[0]
        sub_count = sid_bytes[1]
        authority = int.from_bytes(sid_bytes[2:8], "big")
        subs = []
        for i in range(sub_count):
            base = 8 + i * 4
            if base + 4 > len(sid_bytes):
                break
            subs.append(struct.unpack_from("<I", sid_bytes, base)[0])
        return "S-" + "-".join([str(revision), str(authority), *map(str, subs)])


def _from_unix(value: int) -> datetime:
    try:
        return datetime.fromtimestamp(value, tz=timezone.utc)
    except (OverflowError, OSError, ValueError):
        return datetime(1601, 1, 1, tzinfo=timezone.utc)
