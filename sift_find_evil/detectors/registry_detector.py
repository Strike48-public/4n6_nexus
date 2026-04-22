"""Windows Registry detector: persistence mechanisms and execution from unusual paths.

Consumes parsed Registry artifacts from
``sift_find_evil.parsers.registry_parser`` (Shimcache, Amcache, BAM/DAM,
UserAssist, Run keys) and emits case-agnostic findings.

Three finding classes today:

- ``PERSISTENCE`` findings for Run keys whose command points at a suspicious
  path (user-writable location, bare PowerShell/rundll32 launcher, known
  LOLBAS). One finding per Run key entry that trips the rules.

- ``PERSISTENCE`` findings for Amcache/Shimcache/BAM entries whose file path
  lives in a historically-attacker-writable directory (``\\Users\\Public\\``,
  ``\\AppData\\Local\\Temp\\``, ``\\ProgramData\\``, ``\\Windows\\Temp\\``,
  etc.) AND the basename is a double-extension or unsigned-publisher binary.
  Grouped by file path so 200 BAM rows for one binary collapse to one finding.

- ``PERSISTENCE`` findings for UserAssist entries with zero focus time and a
  script-host basename — the GUI shell logged a "run" but no window ever
  rendered, which fits scheduled/scripted launch patterns.

Addresses SFE-tcs.
"""

from __future__ import annotations

import re
from typing import Iterable, Optional

from ..findings import FindingCategory
from ..parsers.registry_parser import (
    AmcacheEntry,
    BAMEntry,
    RunKeyEntry,
    ShimcacheEntry,
    UserAssistEntry,
)
from ..self_correction.engine import Finding


# --- defaults ----------------------------------------------------------------

_SUSPICIOUS_PATH_FRAGMENTS: tuple[str, ...] = (
    "\\users\\public\\",
    "\\appdata\\local\\temp\\",
    "\\appdata\\roaming\\",
    "\\programdata\\",
    "\\windows\\temp\\",
    "\\recycle.bin\\",
    "\\$recycle.bin\\",
    "\\perflogs\\",
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

# Run key commands that bake encoded/hidden payload arguments.
# Flat alternation (no nested optional groups) to avoid pathological
# backtracking if an adversary drops a giant value into a Run key.
_HIDDEN_POWERSHELL_FLAGS = re.compile(
    r"(?:^|\s)-(?:encodedcommand|enc|e|w\s+hidden|windowstyle\s+hidden|noprofile|nop|executionpolicy\s+bypass|ep\s+bypass)\b",
    re.IGNORECASE,
)

# Hard cap on command length sent to the regex. Real Run key commands are
# well under 2kB; anything longer is malformed or adversarial input and we
# don't want to spend regex time on it.
_MAX_COMMAND_LENGTH = 4096

_PAYLOAD_EXTENSIONS: frozenset[str] = frozenset(
    {"exe", "dll", "scr", "com", "bat", "vbs", "js", "jse", "wsf", "ps1", "lnk"}
)

_DOUBLE_EXT_RE = re.compile(
    r"\.(?:doc|docx|xls|xlsx|pdf|txt|jpg|png|mp3|mp4)\.(?:exe|scr|com|bat|vbs|js|jse|wsf|lnk|ps1)$",
    re.IGNORECASE,
)


def _basename(path: str) -> str:
    """Return the final path component, handling Windows and POSIX separators."""
    if not path:
        return ""
    normalized = path.replace("/", "\\")
    return normalized.rsplit("\\", 1)[-1]


def _in_suspicious_directory(path: str) -> Optional[str]:
    """Return the fragment that matched, or None."""
    lowered = path.lower()
    for fragment in _SUSPICIOUS_PATH_FRAGMENTS:
        if fragment in lowered:
            return fragment.strip("\\")
    return None


def _is_double_extension(name: str) -> bool:
    return bool(_DOUBLE_EXT_RE.search(name))


def _command_path_tokens(command: str) -> list[str]:
    """Split a Windows-style command line into path-looking tokens.

    Handles quoted executables and path arguments. Good enough for the
    heuristic — we're not trying to be a real shell parser, just to look at
    each path-shaped token so double-extension checks can apply to both the
    launcher and its argument (e.g. powershell.exe -f C:\\x\\resume.pdf.lnk).
    """
    tokens: list[str] = []
    buf: list[str] = []
    in_quote = False
    for ch in command.strip():
        if ch == '"':
            in_quote = not in_quote
            continue
        if ch.isspace() and not in_quote:
            if buf:
                tokens.append("".join(buf))
                buf = []
            continue
        buf.append(ch)
    if buf:
        tokens.append("".join(buf))
    return tokens


# --- detector ---------------------------------------------------------------


class RegistryDetector:
    """Emit findings from parsed Registry artifacts.

    Parameters
    ----------
    suspicious_path_fragments:
        Directory-substring list used to flag user-writable drop paths.
        Matched case-insensitively against ``file_path``. Default covers the
        usual Public/AppData/ProgramData/Windows Temp locations.
    lolbas_launchers:
        Interpreter basenames that are suspicious when wired to a Run key.
    """

    def __init__(
        self,
        suspicious_path_fragments: Optional[Iterable[str]] = None,
        lolbas_launchers: Optional[Iterable[str]] = None,
    ):
        self.suspicious_path_fragments = (
            tuple(s.lower() for s in suspicious_path_fragments)
            if suspicious_path_fragments
            else _SUSPICIOUS_PATH_FRAGMENTS
        )
        self.lolbas_launchers = (
            frozenset(n.lower() for n in lolbas_launchers)
            if lolbas_launchers
            else _LOLBAS_LAUNCHERS
        )

    def analyze(
        self,
        shimcache: Optional[Iterable[ShimcacheEntry]] = None,
        amcache: Optional[Iterable[AmcacheEntry]] = None,
        bam: Optional[Iterable[BAMEntry]] = None,
        userassist: Optional[Iterable[UserAssistEntry]] = None,
        run_keys: Optional[Iterable[RunKeyEntry]] = None,
    ) -> list[Finding]:
        """Return findings across all supplied registry streams."""
        findings: list[Finding] = []

        if run_keys is not None:
            findings.extend(self._analyze_run_keys(run_keys))

        findings.extend(self._analyze_executions(shimcache, amcache, bam))

        if userassist is not None:
            findings.extend(self._analyze_userassist(userassist))

        return findings

    # --- Run keys -----------------------------------------------------------

    def _analyze_run_keys(self, run_keys: Iterable[RunKeyEntry]) -> list[Finding]:
        findings: list[Finding] = []
        for entry in run_keys:
            reasons = self._run_key_reasons(entry)
            if not reasons:
                continue
            findings.append(self._build_run_key_finding(entry, reasons))
        return findings

    def _run_key_reasons(self, entry: RunKeyEntry) -> list[str]:
        """Return one reason string per suspicious signal in a Run key."""
        reasons: list[str] = []
        command = entry.command
        lowered = command.lower()

        suspicious_dir = self._match_suspicious_dir(lowered)
        if suspicious_dir is not None:
            reasons.append(
                f"Command path lives under '{suspicious_dir}' (user-writable)"
            )

        launcher = self._launcher_basename(command)
        if launcher is not None and launcher in self.lolbas_launchers:
            reasons.append(f"Launcher '{launcher}' is a LOLBAS/script host")

        if len(command) <= _MAX_COMMAND_LENGTH and _HIDDEN_POWERSHELL_FLAGS.search(
            command
        ):
            reasons.append("Command uses hidden/encoded/bypass launcher flags")

        for token in _command_path_tokens(command):
            if _is_double_extension(_basename(token)):
                reasons.append("Command target uses a double extension")
                break

        return reasons

    @staticmethod
    def _match_suspicious_dir(lowered_command: str) -> Optional[str]:
        for fragment in _SUSPICIOUS_PATH_FRAGMENTS:
            if fragment in lowered_command:
                return fragment.strip("\\")
        return None

    @staticmethod
    def _score_run_key(reasons: list[str]) -> tuple[float, str, str]:
        """Map the reason list to (confidence, label, severity).

        Rationale: a single path-only reason ("lives under ProgramData") is
        generic — legitimate updaters write there. A single strong reason
        (LOLBAS host, hidden flags, double-extension) is already suspicious on
        its own. Two or more reasons of any kind is a clear persistence signal.
        """
        if len(reasons) >= 2:
            return 0.80, "High", "high"
        only = reasons[0].lower()
        is_path_only = "lives under" in only
        if is_path_only:
            return 0.50, "Low", "medium"
        return 0.65, "Medium", "medium"

    def _run_key_target_basename(self, command: str, launcher: str) -> str:
        """Pick the basename that best identifies the persisted payload.

        When the launcher itself is a LOLBAS/script host (powershell.exe,
        rundll32.exe, ...), the meaningful artifact for case-level accounting
        is the payload token, not the interpreter. Scan remaining tokens for
        the first path-like basename with an executable/script extension.
        Fall back to the launcher when no payload token is present (bare
        ``regsvr32.exe /s /u scrobj.dll`` style commands where the payload is
        an argument without a recognisable extension).
        """
        tokens = _command_path_tokens(command)
        if launcher in self.lolbas_launchers and len(tokens) > 1:
            for token in tokens[1:]:
                name = _basename(token).lower()
                if name and name != launcher and "." in name:
                    suffix = name.rsplit(".", 1)[-1]
                    if suffix in _PAYLOAD_EXTENSIONS:
                        return name
        return launcher

    @staticmethod
    def _launcher_basename(command: str) -> Optional[str]:
        """Extract the executable basename from a Run key command line."""
        if not command.strip():
            return None
        stripped = command.strip()
        if stripped.startswith('"'):
            end = stripped.find('"', 1)
            if end == -1:
                return None
            executable = stripped[1:end]
        else:
            executable = stripped.split()[0]
        return _basename(executable).lower()

    def _build_run_key_finding(self, entry: RunKeyEntry, reasons: list[str]) -> Finding:
        launcher = self._launcher_basename(entry.command) or "(unknown)"
        target_basename = self._run_key_target_basename(entry.command, launcher)
        confidence, label, severity = self._score_run_key(reasons)
        return Finding(
            title=(
                f"Suspicious Run key: {entry.hive} \\{entry.key_path}"
                f" -> {entry.value_name}"
            ),
            description=(
                f"Registry persistence value '{entry.value_name}' under "
                f"{entry.hive}\\{entry.key_path} runs "
                f"'{entry.command}' at logon. Suspicious because: "
                f"{'; '.join(reasons)}."
            ),
            finding_type="behavior",
            severity=severity,
            category=FindingCategory.PERSISTENCE,
            evidence={
                "hive": entry.hive,
                "key_path": entry.key_path,
                "value_name": entry.value_name,
                "command": entry.command,
                "launcher": launcher,
                "executable": target_basename,
                "last_write_time": entry.last_write_time.isoformat(),
                "reasons": reasons,
            },
            confidence=confidence,
            confidence_label=label,
            reasoning_chain=[
                f"{entry.hive}\\{entry.key_path} Run key points at {launcher}.",
                *reasons,
                self._run_key_summary_line(reasons),
            ],
            artifact_sources=["registry"],
        )

    @staticmethod
    def _run_key_summary_line(reasons: list[str]) -> str:
        if len(reasons) >= 2:
            return "Multiple independent signals fired."
        if "lives under" in reasons[0].lower():
            return (
                "Only a generic path signal fired; many legitimate updaters "
                "also drop into user-writable directories."
            )
        return "Single strong signal fired; investigate context before acting."

    # --- Shimcache / Amcache / BAM execution from unusual paths -------------

    def _analyze_executions(
        self,
        shimcache: Optional[Iterable[ShimcacheEntry]],
        amcache: Optional[Iterable[AmcacheEntry]],
        bam: Optional[Iterable[BAMEntry]],
    ) -> list[Finding]:
        grouped: dict[str, dict] = {}

        for entry in shimcache or ():
            reason = self._path_reason(entry.file_path)
            if reason is None:
                continue
            self._add_exec_hit(
                grouped,
                file_path=entry.file_path,
                source="shimcache",
                timestamp=entry.last_modified.isoformat(),
                reason=reason,
                extra={"exec_flag": entry.exec_flag, "file_size": entry.file_size},
            )

        for entry in amcache or ():
            reason = self._path_reason(entry.file_path)
            if reason is None:
                continue
            self._add_exec_hit(
                grouped,
                file_path=entry.file_path,
                source="amcache",
                timestamp=entry.first_execution.isoformat(),
                reason=reason,
                extra={
                    "sha1": entry.sha1_hash,
                    "publisher": entry.publisher,
                    "file_size": entry.file_size,
                },
            )

        for entry in bam or ():
            reason = self._path_reason(entry.file_path)
            if reason is None:
                continue
            self._add_exec_hit(
                grouped,
                file_path=entry.file_path,
                source="bam",
                timestamp=entry.execution_time.isoformat(),
                reason=reason,
                extra={"user_sid": entry.user_sid},
            )

        return [
            self._build_exec_finding(path, bundle)
            for path, bundle in sorted(grouped.items())
        ]

    def _path_reason(self, file_path: str) -> Optional[str]:
        """Decide whether an execution entry is worth flagging, and why."""
        suspicious_dir = _in_suspicious_directory(file_path)
        if suspicious_dir is None:
            return None
        basename = _basename(file_path)
        if _is_double_extension(basename):
            return (
                f"Execution from '{suspicious_dir}' with double-extension "
                f"filename '{basename}'"
            )
        return f"Execution from attacker-writable directory '{suspicious_dir}'"

    @staticmethod
    def _add_exec_hit(
        grouped: dict[str, dict],
        *,
        file_path: str,
        source: str,
        timestamp: str,
        reason: str,
        extra: dict,
    ) -> None:
        key = file_path.lower()
        bundle = grouped.setdefault(
            key,
            {
                "file_path": file_path,
                "sources": set(),
                "timestamps": [],
                "reasons": set(),
                "details": [],
            },
        )
        bundle["sources"].add(source)
        bundle["timestamps"].append((source, timestamp))
        bundle["reasons"].add(reason)
        bundle["details"].append({"source": source, "timestamp": timestamp, **extra})

    def _build_exec_finding(self, path_key: str, bundle: dict) -> Finding:
        file_path = bundle["file_path"]
        sources = sorted(bundle["sources"])
        reasons = sorted(bundle["reasons"])
        timestamps = sorted(t for _, t in bundle["timestamps"])
        first_seen = timestamps[0]
        last_seen = timestamps[-1]
        double_ext = any("double-extension" in r for r in reasons)
        base_conf = 0.70 if double_ext else 0.55
        if len(sources) >= 2:
            base_conf = min(0.90, base_conf + 0.15)
        return Finding(
            title=f"Execution from attacker-writable path: {_basename(file_path)}",
            description=(
                f"{file_path} executed, recorded by {', '.join(sources)}. "
                f"Reason(s): {'; '.join(reasons)}."
            ),
            finding_type="indicator",
            severity="high" if double_ext else "medium",
            category=FindingCategory.PERSISTENCE,
            evidence={
                "file_path": file_path,
                "executable": _basename(file_path).lower(),
                "sources": sources,
                "first_seen": first_seen,
                "last_seen": last_seen,
                "reasons": reasons,
                "details": bundle["details"],
            },
            confidence=round(base_conf, 2),
            confidence_label="High" if base_conf >= 0.75 else "Medium",
            reasoning_chain=[
                f"{file_path} was recorded by {', '.join(sources)}.",
                *reasons,
                (
                    f"Corroborating sources ({len(sources)}) strengthen the signal."
                    if len(sources) >= 2
                    else "Single-source signal; corroborate with Prefetch or MFT."
                ),
            ],
            artifact_sources=["registry"],
        )

    # --- UserAssist ---------------------------------------------------------

    def _analyze_userassist(
        self, userassist: Iterable[UserAssistEntry]
    ) -> list[Finding]:
        findings: list[Finding] = []
        for entry in userassist:
            basename = _basename(entry.program_name).lower()
            if basename in self.lolbas_launchers and entry.focus_time_ms == 0:
                findings.append(self._build_userassist_finding(entry))
        return findings

    def _build_userassist_finding(self, entry: UserAssistEntry) -> Finding:
        return Finding(
            title=f"UserAssist shell-invoked launcher with no window focus: {entry.program_name}",
            description=(
                f"UserAssist recorded {entry.run_count} shell invocation(s) of "
                f"{entry.program_name} but logged zero focus time. Script hosts "
                f"launched from Explorer normally still receive focus briefly; "
                f"zero focus is consistent with silent/scripted execution."
            ),
            finding_type="indicator",
            severity="medium",
            category=FindingCategory.PERSISTENCE,
            evidence={
                "program_name": entry.program_name,
                "executable": _basename(entry.program_name).lower(),
                "run_count": entry.run_count,
                "focus_count": entry.focus_count,
                "focus_time_ms": entry.focus_time_ms,
                "last_execution": entry.last_execution.isoformat(),
            },
            confidence=0.55,
            confidence_label="Medium",
            reasoning_chain=[
                f"{entry.program_name} is a script/launcher host.",
                f"UserAssist records {entry.run_count} runs but 0 ms of focus.",
                "Silent GUI-shell launches fit scripted/unattended invocation.",
            ],
            artifact_sources=["registry"],
        )
