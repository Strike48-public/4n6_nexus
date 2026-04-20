"""LNK and Jump List parsers — document-access and removable-media evidence.

Windows records two artifact families that reveal which files a user opened
and where those files lived:

- **LNK files** (``*.lnk``). Every time Explorer opens a file, a shortcut is
  written to ``%AppData%\\Microsoft\\Windows\\Recent\\`` (or similar).
  The LNK body carries the target's full path, size, MAC times, drive type
  (fixed / removable / network), volume serial, and — historically — the
  originating machine's hostname and MAC address. Useful for reconstructing
  file access even when the target file is long gone.

- **Jump Lists** (``*.automaticDestinations-ms``, ``*.customDestinations-ms``).
  Per-application MRU lists stored under
  ``%AppData%\\Microsoft\\Windows\\Recent\\{Automatic,Custom}Destinations``.
  Tied to a stable AppID so "Excel opened this spreadsheet" is recoverable
  even across renames.

This module parses CSV exports from RECmd / LECmd / JLECmd (Eric Zimmerman's
tools). Direct binary parsing of LNK / DestList streams is out of scope for
the first pass — the CSV bridge is what SIFT analysts actually produce.

Addresses SFE-c6s (Phase 2 parser half).
"""

from __future__ import annotations

import csv
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


# --- dataclasses ------------------------------------------------------------


@dataclass(frozen=True)
class LnkEntry:
    """A single parsed Windows shortcut (.lnk) record.

    Attributes
    ----------
    lnk_path:
        Absolute path to the .lnk file on the evidence image. The parent
        directory tells you whether the shortcut lived under the user's
        Recent folder, a Startup folder (persistence), or elsewhere.
    target_path:
        The file the shortcut points at. May be empty if the LNK was a
        command-only shortcut.
    target_size:
        Size (bytes) of the target at LNK-creation time.
    target_created, target_modified, target_accessed:
        MAC times of the target at LNK-creation time. Can be absent.
    working_directory, arguments:
        From the LNK header. Non-empty arguments on a document shortcut is
        unusual and worth attention (e.g., ``resume.docx -Command ...``).
    drive_type:
        ``fixed``, ``removable``, ``network``, ``cdrom``, ``ramdisk``,
        ``unknown``. Derived from the VolumeID flags.
    volume_serial, volume_label:
        From the VolumeID block; identifies removable media across mounts.
    machine_id, mac_address:
        From the TrackerDataBlock. Useful for attributing a LNK dropped
        on this machine to the attacker's workstation.
    created:
        Creation time of the LNK file itself on disk. Separate from the
        target MAC times — this is when the user (or script) opened the
        target and caused Explorer to write the LNK.
    """

    lnk_path: str
    target_path: str
    target_size: Optional[int]
    target_created: Optional[datetime]
    target_modified: Optional[datetime]
    target_accessed: Optional[datetime]
    working_directory: str
    arguments: str
    drive_type: str
    volume_serial: Optional[str]
    volume_label: Optional[str]
    machine_id: Optional[str]
    mac_address: Optional[str]
    created: Optional[datetime]

    def __post_init__(self) -> None:
        if not self.lnk_path:
            raise ValueError("LNK path cannot be empty")


@dataclass(frozen=True)
class JumpListEntry:
    """A single Jump List MRU record.

    Attributes
    ----------
    app_id:
        Hex AppID that names the owning application (e.g. the
        32-hex-char tag Excel uses). See WinAppIDs reference lists for the
        mapping.
    app_name:
        Human-readable name if the parser resolved the AppID, else empty.
    entry_type:
        ``automatic`` (Windows-managed recent list) or ``custom`` (pinned
        / task-defined list). Automatic is the richer evidence source.
    target_path:
        File the app opened. Can be a local path or a UNC share.
    drive_type:
        Same vocabulary as :class:`LnkEntry`.
    opened_time:
        When the app opened this target.
    jumplist_path:
        Absolute path to the ``.automaticDestinations-ms`` /
        ``.customDestinations-ms`` file that supplied the entry.
    """

    app_id: str
    app_name: str
    entry_type: str  # "automatic" | "custom"
    target_path: str
    drive_type: str
    opened_time: Optional[datetime]
    jumplist_path: str

    def __post_init__(self) -> None:
        if self.entry_type not in ("automatic", "custom"):
            raise ValueError(
                f"Invalid jumplist entry_type: {self.entry_type!r} "
                "(must be 'automatic' or 'custom')"
            )
        if not self.app_id:
            raise ValueError("AppID cannot be empty")


# --- helpers ----------------------------------------------------------------


_DRIVE_TYPE_ALIASES: dict[str, str] = {
    "fixed": "fixed",
    "drive_fixed": "fixed",
    "drivefixed": "fixed",
    "removable": "removable",
    "drive_removable": "removable",
    "driveremovable": "removable",
    "network": "network",
    "remote": "network",
    "drive_remote": "network",
    "driveremote": "network",
    "cdrom": "cdrom",
    "drive_cdrom": "cdrom",
    "drivecdrom": "cdrom",
    "ramdisk": "ramdisk",
    "drive_ramdisk": "ramdisk",
    "driveramdisk": "ramdisk",
    "": "unknown",
    "unknown": "unknown",
    "no_root_dir": "unknown",
    "drive_no_root_dir": "unknown",
}


def _normalize_drive_type(raw: str) -> str:
    """Map tool-specific drive-type strings to a compact vocabulary."""
    if raw is None:
        return "unknown"
    key = raw.strip().lower().replace(" ", "_").replace("-", "_")
    return _DRIVE_TYPE_ALIASES.get(key, "unknown")


def _parse_timestamp(value: str) -> Optional[datetime]:
    """Parse a timestamp cell, returning None for empty / unparseable input."""
    if not value:
        return None
    cleaned = value.strip()
    if not cleaned:
        return None
    # Strip trailing timezone suffixes LECmd emits that fromisoformat pre-3.11
    # would choke on. Python 3.11+ handles "Z" natively, but be defensive.
    if cleaned.endswith("Z"):
        cleaned = cleaned[:-1] + "+00:00"
    try:
        ts = datetime.fromisoformat(cleaned.replace(" ", "T", 1))
    except ValueError:
        logger.debug("Unparseable timestamp: %r", value)
        return None
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return ts


def _parse_optional_int(value: str) -> Optional[int]:
    if not value:
        return None
    cleaned = value.strip()
    if not cleaned:
        return None
    try:
        return int(cleaned)
    except ValueError:
        logger.debug("Unparseable integer: %r", value)
        return None


# Max path/argument length we carry through the pipeline. Real LNKs stay well
# under 4 KB per field; anything larger is adversarial or malformed CSV input.
_MAX_FIELD_LENGTH = 4096


def _first_nonempty(row: dict, *keys: str, default: str = "") -> str:
    """Return the first non-empty value among ``keys`` in ``row``.

    CSV exporters disagree on column names (``TargetPath`` vs ``target_path``
    vs ``LocalPath``). Centralise the alias lookup so the parser survives
    minor schema drift.

    Strips null bytes and bare CR/LF that could smuggle past downstream path
    checks if an adversarial CSV is under analysis, and truncates oversize
    cells to ``_MAX_FIELD_LENGTH`` so downstream regexes never see pathological
    inputs.
    """
    for key in keys:
        if key in row and row[key]:
            raw = row[key]
            cleaned = (
                raw.replace("\x00", "").replace("\r", "").replace("\n", "").strip()
            )
            if cleaned:
                return cleaned[:_MAX_FIELD_LENGTH]
    return default


# --- parsers ----------------------------------------------------------------


class LnkParser:
    """Parse LECmd (or equivalent) CSV exports of .lnk files."""

    def parse_csv(self, csv_path: Path) -> list[LnkEntry]:
        """Parse a CSV of LNK entries into ``LnkEntry`` objects.

        The CSV is expected to be a LECmd export. Column names tolerated:

        - ``SourceFile`` / ``lnk_path``
        - ``LocalPath`` / ``TargetPath`` / ``target_path``
        - ``FileSize`` / ``TargetFileSize`` / ``target_size``
        - ``TargetCreated`` / ``target_created``
        - ``TargetModified`` / ``target_modified``
        - ``TargetAccessed`` / ``target_accessed``
        - ``WorkingDirectory`` / ``working_directory``
        - ``Arguments`` / ``arguments``
        - ``DriveType`` / ``drive_type``
        - ``VolumeSerialNumber`` / ``volume_serial``
        - ``VolumeLabel`` / ``volume_label``
        - ``MachineID`` / ``machine_id``
        - ``MACAddress`` / ``mac_address``
        - ``SourceCreated`` / ``created``

        Missing columns are tolerated; required ``lnk_path`` is not.
        """
        if not csv_path.exists():
            raise FileNotFoundError(f"LNK CSV not found: {csv_path}")

        entries: list[LnkEntry] = []
        try:
            with csv_path.open("r", encoding="utf-8-sig", newline="") as fh:
                reader = csv.DictReader(fh)
                for row in reader:
                    lnk_path = _first_nonempty(row, "SourceFile", "lnk_path")
                    if not lnk_path:
                        # Row with no source path is garbage; skip quietly.
                        continue
                    entries.append(
                        LnkEntry(
                            lnk_path=lnk_path,
                            target_path=_first_nonempty(
                                row, "LocalPath", "TargetPath", "target_path"
                            ),
                            target_size=_parse_optional_int(
                                _first_nonempty(
                                    row,
                                    "FileSize",
                                    "TargetFileSize",
                                    "target_size",
                                )
                            ),
                            target_created=_parse_timestamp(
                                _first_nonempty(row, "TargetCreated", "target_created")
                            ),
                            target_modified=_parse_timestamp(
                                _first_nonempty(row, "TargetModified", "target_modified")
                            ),
                            target_accessed=_parse_timestamp(
                                _first_nonempty(row, "TargetAccessed", "target_accessed")
                            ),
                            working_directory=_first_nonempty(
                                row, "WorkingDirectory", "working_directory"
                            ),
                            arguments=_first_nonempty(row, "Arguments", "arguments"),
                            drive_type=_normalize_drive_type(
                                _first_nonempty(row, "DriveType", "drive_type")
                            ),
                            volume_serial=_first_nonempty(
                                row, "VolumeSerialNumber", "volume_serial"
                            )
                            or None,
                            volume_label=_first_nonempty(
                                row, "VolumeLabel", "volume_label"
                            )
                            or None,
                            machine_id=_first_nonempty(
                                row, "MachineID", "machine_id"
                            )
                            or None,
                            mac_address=_first_nonempty(
                                row, "MACAddress", "mac_address"
                            )
                            or None,
                            created=_parse_timestamp(
                                _first_nonempty(row, "SourceCreated", "created")
                            ),
                        )
                    )
        except csv.Error as exc:
            raise ValueError(f"Invalid LNK CSV format in {csv_path}: {exc}") from exc

        logger.info("Parsed %d LNK entries from %s", len(entries), csv_path)
        return entries


class JumpListParser:
    """Parse JLECmd (or equivalent) CSV exports of Jump List MRU entries."""

    def parse_csv(self, csv_path: Path) -> list[JumpListEntry]:
        """Parse a CSV of Jump List entries into ``JumpListEntry`` objects.

        Column names tolerated:

        - ``SourceFile`` / ``jumplist_path``
        - ``AppId`` / ``AppID`` / ``app_id``
        - ``AppIdDescription`` / ``AppName`` / ``app_name``
        - ``EntryType`` / ``entry_type`` — values ``Automatic`` /
          ``Custom`` (case-insensitive).
        - ``LocalPath`` / ``TargetPath`` / ``target_path``
        - ``DriveType`` / ``drive_type``
        - ``LastModified`` / ``OpenedTime`` / ``opened_time``

        Rows missing both ``target_path`` and ``app_id`` are skipped.
        """
        if not csv_path.exists():
            raise FileNotFoundError(f"Jump List CSV not found: {csv_path}")

        entries: list[JumpListEntry] = []
        try:
            with csv_path.open("r", encoding="utf-8-sig", newline="") as fh:
                reader = csv.DictReader(fh)
                for row in reader:
                    app_id = _first_nonempty(row, "AppId", "AppID", "app_id")
                    target_path = _first_nonempty(
                        row, "LocalPath", "TargetPath", "target_path"
                    )
                    if not app_id and not target_path:
                        continue
                    if not app_id:
                        # Entry with a target but no AppID is still useful as a
                        # file-access record; synthesize a placeholder so the
                        # dataclass validator passes.
                        app_id = "(unknown)"
                    entry_type_raw = _first_nonempty(
                        row, "EntryType", "entry_type", default="Automatic"
                    ).lower()
                    entry_type = (
                        "custom" if "custom" in entry_type_raw else "automatic"
                    )
                    entries.append(
                        JumpListEntry(
                            app_id=app_id,
                            app_name=_first_nonempty(
                                row, "AppIdDescription", "AppName", "app_name"
                            ),
                            entry_type=entry_type,
                            target_path=target_path,
                            drive_type=_normalize_drive_type(
                                _first_nonempty(row, "DriveType", "drive_type")
                            ),
                            opened_time=_parse_timestamp(
                                _first_nonempty(
                                    row, "LastModified", "OpenedTime", "opened_time"
                                )
                            ),
                            jumplist_path=_first_nonempty(
                                row, "SourceFile", "jumplist_path"
                            ),
                        )
                    )
        except csv.Error as exc:
            raise ValueError(f"Invalid Jump List CSV format in {csv_path}: {exc}") from exc

        logger.info(
            "Parsed %d Jump List entries from %s", len(entries), csv_path
        )
        return entries
