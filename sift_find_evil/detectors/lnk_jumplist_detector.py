"""LNK and Jump List detector: document access, removable-media exfil, startup persistence.

Consumes parsed ``LnkEntry`` and ``JumpListEntry`` records from
``sift_find_evil.parsers.lnk_jumplist_parser`` and emits case-agnostic Findings.

Three finding classes today:

- ``DATA_EXFILTRATION`` — target lived on removable or network media, and has
  a sensitive extension (documents, databases, archives, secrets). Applies to
  both LNK and Jump List entries. Grouped per target path so 200 LNK rows for
  one file collapse to one finding.

- ``PERSISTENCE`` — an LNK file under a Startup folder that launches a LOLBAS
  interpreter, a user-writable path, or carries suspicious command arguments.
  Shortcut-in-Startup is the classic auto-run pattern that survives reboot.

- ``DATA_EXFILTRATION`` (low-confidence indicator) — Jump List entries whose
  target is a UNC path (``\\\\server\\share\\...``) for a sensitive extension.
  UNC-only Jump List hits without removable/network drive-type metadata are a
  weaker signal; reported at medium severity so an analyst can pivot.

Addresses SFE-c6s (detector half).
"""

from __future__ import annotations

import re
from typing import Iterable, Optional

from ..findings import FindingCategory
from ..parsers.lnk_jumplist_parser import JumpListEntry, LnkEntry
from ..self_correction.engine import Finding


# --- defaults ----------------------------------------------------------------

# Extensions that carry user/business data. Matched case-insensitively against
# the target basename. Intentionally excludes code/binary extensions — those
# show up in plenty of benign LNKs (installer leftovers, portable apps) and
# would drown the signal.
_SENSITIVE_EXTENSIONS: frozenset[str] = frozenset(
    {
        # Office / documents
        "doc", "docx", "docm", "dot", "dotx",
        "xls", "xlsx", "xlsm", "xlsb", "xlt", "xltx",
        "ppt", "pptx", "pptm", "pps", "ppsx",
        "pdf", "rtf", "odt", "ods", "odp",
        "csv", "tsv",
        # Source / config (often carries secrets)
        "pem", "key", "pfx", "p12", "pgp", "asc",
        # Databases / dumps
        "sql", "sqlite", "db", "mdb", "accdb", "bak", "dmp",
        # Archives (staged exfil)
        "zip", "rar", "7z", "tar", "gz", "tgz", "iso",
        # Mail
        "pst", "ost", "msg", "eml",
    }
)

_STARTUP_FOLDER_FRAGMENTS: tuple[str, ...] = (
    "\\microsoft\\windows\\start menu\\programs\\startup\\",
    "\\start menu\\programs\\startup\\",
    "\\startup\\",
)

_LOLBAS_LAUNCHERS: frozenset[str] = frozenset(
    {
        "powershell.exe",
        "pwsh.exe",
        "cmd.exe",
        "rundll32.exe",
        "regsvr32.exe",
        "mshta.exe",
        "wscript.exe",
        "cscript.exe",
        "msbuild.exe",
        "installutil.exe",
        "bitsadmin.exe",
        "certutil.exe",
    }
)

_USER_WRITABLE_FRAGMENTS: tuple[str, ...] = (
    "\\users\\public\\",
    "\\appdata\\local\\temp\\",
    "\\appdata\\roaming\\",
    "\\programdata\\",
    "\\windows\\temp\\",
    "\\recycle.bin\\",
    "\\$recycle.bin\\",
    "\\perflogs\\",
)

# Flat alternation, no nested groups, to avoid catastrophic backtracking if a
# LNK Arguments field carries megabyte-scale adversarial input.
_HIDDEN_POWERSHELL_FLAGS = re.compile(
    r"(?:^|\s)-(?:encodedcommand|enc|e|w\s+hidden|windowstyle\s+hidden|noprofile|nop|executionpolicy\s+bypass|ep\s+bypass)\b",
    re.IGNORECASE,
)

# Hard cap on argument string length before regex. LNK Arguments are normally
# under 2kB; anything larger is adversarial or malformed.
_MAX_ARG_LENGTH = 4096

_UNC_PREFIX_RE = re.compile(r"^\\\\[^\\]+\\[^\\]+")


# --- helpers ----------------------------------------------------------------


def _basename(path: str) -> str:
    """Return the final path component, handling Windows and POSIX separators."""
    if not path:
        return ""
    normalized = path.replace("/", "\\")
    return normalized.rsplit("\\", 1)[-1]


def _extension(name: str) -> str:
    """Return the lowercase extension without the leading dot, or empty."""
    if "." not in name:
        return ""
    return name.rsplit(".", 1)[-1].lower()


def _in_startup_folder(lnk_path: str) -> bool:
    lowered = lnk_path.lower()
    return any(fragment in lowered for fragment in _STARTUP_FOLDER_FRAGMENTS)


def _in_user_writable(path: str) -> Optional[str]:
    if not path:
        return None
    lowered = path.lower()
    for fragment in _USER_WRITABLE_FRAGMENTS:
        if fragment in lowered:
            return fragment.strip("\\")
    return None


def _is_unc_path(path: str) -> bool:
    if not path:
        return False
    return bool(_UNC_PREFIX_RE.match(path))


# --- detector ---------------------------------------------------------------


class LnkJumpListDetector:
    """Emit findings from parsed LNK and Jump List entries.

    Parameters
    ----------
    sensitive_extensions:
        Extensions (without leading dot, lowercase) that mark a target as
        business/user data worth flagging when it lived on removable or
        network media.
    lolbas_launchers:
        Interpreter basenames that are suspicious when a Startup LNK points at
        them.
    """

    def __init__(
        self,
        sensitive_extensions: Optional[Iterable[str]] = None,
        lolbas_launchers: Optional[Iterable[str]] = None,
    ):
        self.sensitive_extensions = (
            frozenset(e.lower().lstrip(".") for e in sensitive_extensions)
            if sensitive_extensions
            else _SENSITIVE_EXTENSIONS
        )
        self.lolbas_launchers = (
            frozenset(n.lower() for n in lolbas_launchers)
            if lolbas_launchers
            else _LOLBAS_LAUNCHERS
        )

    def analyze(
        self,
        lnk_entries: Optional[Iterable[LnkEntry]] = None,
        jumplist_entries: Optional[Iterable[JumpListEntry]] = None,
    ) -> list[Finding]:
        """Return findings across both LNK and Jump List streams."""
        findings: list[Finding] = []
        findings.extend(self._analyze_removable_network(lnk_entries, jumplist_entries))
        if lnk_entries is not None:
            findings.extend(self._analyze_startup_persistence(lnk_entries))
        if jumplist_entries is not None:
            findings.extend(self._analyze_jumplist_unc(jumplist_entries))
        return findings

    # --- Removable / network media access ---------------------------------

    def _analyze_removable_network(
        self,
        lnk_entries: Optional[Iterable[LnkEntry]],
        jumplist_entries: Optional[Iterable[JumpListEntry]],
    ) -> list[Finding]:
        """Group LNK+JumpList hits by target path and emit one finding each."""
        grouped: dict[str, dict] = {}

        for entry in lnk_entries or ():
            target = entry.target_path
            if not target or not self._is_sensitive(target):
                continue
            if entry.drive_type not in ("removable", "network"):
                continue
            self._add_media_hit(
                grouped,
                target_path=target,
                source="lnk",
                drive_type=entry.drive_type,
                timestamp=_iso_or_empty(entry.target_accessed or entry.target_modified or entry.created),
                detail={
                    "lnk_path": entry.lnk_path,
                    "volume_serial": entry.volume_serial,
                    "volume_label": entry.volume_label,
                    "machine_id": entry.machine_id,
                    "mac_address": entry.mac_address,
                    "target_size": entry.target_size,
                },
            )

        for entry in jumplist_entries or ():
            target = entry.target_path
            if not target or not self._is_sensitive(target):
                continue
            if entry.drive_type not in ("removable", "network"):
                continue
            self._add_media_hit(
                grouped,
                target_path=target,
                source="jumplist",
                drive_type=entry.drive_type,
                timestamp=_iso_or_empty(entry.opened_time),
                detail={
                    "jumplist_path": entry.jumplist_path,
                    "app_id": entry.app_id,
                    "app_name": entry.app_name,
                    "entry_type": entry.entry_type,
                },
            )

        return [
            self._build_media_finding(bundle)
            for _, bundle in sorted(grouped.items())
        ]

    def _is_sensitive(self, target_path: str) -> bool:
        return _extension(_basename(target_path)) in self.sensitive_extensions

    @staticmethod
    def _add_media_hit(
        grouped: dict[str, dict],
        *,
        target_path: str,
        source: str,
        drive_type: str,
        timestamp: str,
        detail: dict,
    ) -> None:
        key = target_path.lower()
        bundle = grouped.setdefault(
            key,
            {
                "target_path": target_path,
                "sources": set(),
                "drive_types": set(),
                "timestamps": [],
                "details": [],
            },
        )
        bundle["sources"].add(source)
        bundle["drive_types"].add(drive_type)
        if timestamp:
            bundle["timestamps"].append(timestamp)
        bundle["details"].append({"source": source, "drive_type": drive_type, **detail})

    def _build_media_finding(self, bundle: dict) -> Finding:
        target_path = bundle["target_path"]
        sources = sorted(bundle["sources"])
        drive_types = sorted(bundle["drive_types"])
        timestamps = sorted(bundle["timestamps"])
        first_seen = timestamps[0] if timestamps else ""
        last_seen = timestamps[-1] if timestamps else ""
        extension = _extension(_basename(target_path))
        drive_label = "/".join(drive_types)

        base_conf = 0.65
        if len(sources) >= 2:
            base_conf = min(0.85, base_conf + 0.10)
        if "removable" in drive_types:
            base_conf = min(0.85, base_conf + 0.05)

        return Finding(
            title=f"Sensitive file accessed from {drive_label} media: {_basename(target_path)}",
            description=(
                f"{target_path} (.{extension}) was opened from {drive_label} "
                f"media, recorded by {', '.join(sources)}. Sensitive extensions "
                "accessed from removable or network drives are a common signal "
                "for data staging / exfiltration."
            ),
            finding_type="indicator",
            severity="high" if "removable" in drive_types else "medium",
            category=FindingCategory.DATA_EXFILTRATION,
            evidence={
                "target_path": target_path,
                "extension": extension,
                "sources": sources,
                "drive_types": drive_types,
                "first_seen": first_seen,
                "last_seen": last_seen,
                "details": bundle["details"],
            },
            confidence=round(base_conf, 2),
            confidence_label="High" if base_conf >= 0.75 else "Medium",
            reasoning_chain=[
                f"{target_path} has a sensitive extension (.{extension}).",
                f"Target lived on {drive_label} media per drive-type metadata.",
                (
                    f"Corroborated by {', '.join(sources)} ({len(sources)} sources)."
                    if len(sources) >= 2
                    else f"Single-source hit from {sources[0]}; corroborate with USB/PCAP."
                ),
            ],
            artifact_sources=["lnk_jumplist"],
        )

    # --- Startup-folder persistence ---------------------------------------

    def _analyze_startup_persistence(
        self, lnk_entries: Iterable[LnkEntry]
    ) -> list[Finding]:
        findings: list[Finding] = []
        for entry in lnk_entries:
            if not _in_startup_folder(entry.lnk_path):
                continue
            reasons = self._startup_reasons(entry)
            if not reasons:
                continue
            findings.append(self._build_startup_finding(entry, reasons))
        return findings

    def _startup_reasons(self, entry: LnkEntry) -> list[str]:
        reasons: list[str] = []
        target_basename = _basename(entry.target_path).lower()
        if target_basename in self.lolbas_launchers:
            reasons.append(
                f"Startup shortcut launches LOLBAS/script host '{target_basename}'"
            )
        writable_fragment = _in_user_writable(entry.target_path)
        if writable_fragment is not None:
            reasons.append(
                f"Startup shortcut target lives under '{writable_fragment}' (user-writable)"
            )
        arguments = entry.arguments or ""
        if (
            arguments
            and len(arguments) <= _MAX_ARG_LENGTH
            and _HIDDEN_POWERSHELL_FLAGS.search(arguments)
        ):
            reasons.append(
                "Startup shortcut carries hidden/encoded/bypass launcher flags"
            )
        return reasons

    def _build_startup_finding(
        self, entry: LnkEntry, reasons: list[str]
    ) -> Finding:
        target_basename = _basename(entry.target_path) or "(no target)"
        confidence, label, severity = self._score_startup(reasons)
        return Finding(
            title=f"Startup shortcut: {_basename(entry.lnk_path)} -> {target_basename}",
            description=(
                f"Shortcut {entry.lnk_path} sits in a Startup folder and runs "
                f"{entry.target_path or '(command-only)'} "
                f"{(entry.arguments or '').strip()} at logon. Suspicious "
                f"because: {'; '.join(reasons)}."
            ),
            finding_type="behavior",
            severity=severity,
            category=FindingCategory.PERSISTENCE,
            evidence={
                "lnk_path": entry.lnk_path,
                "target_path": entry.target_path,
                "arguments": entry.arguments,
                "working_directory": entry.working_directory,
                "drive_type": entry.drive_type,
                "reasons": reasons,
            },
            confidence=confidence,
            confidence_label=label,
            reasoning_chain=[
                f"{entry.lnk_path} lives in a Startup folder (auto-runs at logon).",
                *reasons,
                (
                    "Multiple independent signals fired."
                    if len(reasons) >= 2
                    else "Single strong signal fired; investigate context before acting."
                ),
            ],
            artifact_sources=["lnk_jumplist"],
        )

    @staticmethod
    def _score_startup(reasons: list[str]) -> tuple[float, str, str]:
        if len(reasons) >= 2:
            return 0.80, "High", "high"
        return 0.65, "Medium", "medium"

    # --- Jump List UNC document access ------------------------------------

    def _analyze_jumplist_unc(
        self, jumplist_entries: Iterable[JumpListEntry]
    ) -> list[Finding]:
        grouped: dict[str, dict] = {}

        for entry in jumplist_entries:
            target = entry.target_path
            if not target or not _is_unc_path(target):
                continue
            if not self._is_sensitive(target):
                continue
            # Avoid double-reporting when drive_type already marked as network
            # (handled by _analyze_removable_network).
            if entry.drive_type in ("removable", "network"):
                continue
            key = target.lower()
            bundle = grouped.setdefault(
                key,
                {
                    "target_path": target,
                    "app_ids": set(),
                    "timestamps": [],
                    "details": [],
                },
            )
            bundle["app_ids"].add(entry.app_id)
            ts = _iso_or_empty(entry.opened_time)
            if ts:
                bundle["timestamps"].append(ts)
            bundle["details"].append(
                {
                    "jumplist_path": entry.jumplist_path,
                    "app_id": entry.app_id,
                    "app_name": entry.app_name,
                    "entry_type": entry.entry_type,
                    "opened_time": ts,
                }
            )

        return [
            self._build_jumplist_unc_finding(bundle)
            for _, bundle in sorted(grouped.items())
        ]

    @staticmethod
    def _build_jumplist_unc_finding(bundle: dict) -> Finding:
        target_path = bundle["target_path"]
        app_ids = sorted(bundle["app_ids"])
        timestamps = sorted(bundle["timestamps"])
        first_seen = timestamps[0] if timestamps else ""
        last_seen = timestamps[-1] if timestamps else ""
        extension = _extension(_basename(target_path))
        return Finding(
            title=f"Jump List access to UNC share: {_basename(target_path)}",
            description=(
                f"Jump List records {len(bundle['details'])} open(s) of "
                f"{target_path} (.{extension}) across {len(app_ids)} "
                "application(s). UNC-share access to sensitive files is a "
                "common document-exfil signal."
            ),
            finding_type="indicator",
            severity="medium",
            category=FindingCategory.DATA_EXFILTRATION,
            evidence={
                "target_path": target_path,
                "extension": extension,
                "app_ids": app_ids,
                "first_seen": first_seen,
                "last_seen": last_seen,
                "details": bundle["details"],
            },
            confidence=0.55,
            confidence_label="Medium",
            reasoning_chain=[
                f"{target_path} is a UNC-share path for a sensitive file type (.{extension}).",
                f"Accessed by {len(app_ids)} application(s) per Jump List.",
                "Drive-type metadata did not pre-flag this as a network mount; report as a weaker signal.",
            ],
            artifact_sources=["lnk_jumplist"],
        )


def _iso_or_empty(value) -> str:
    """Serialize a datetime to ISO format, or empty string if absent."""
    if value is None:
        return ""
    return value.isoformat()
