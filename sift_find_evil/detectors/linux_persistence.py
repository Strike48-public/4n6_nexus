"""Linux persistence detector.

The engine's registry/prefetch/BAM detectors are Windows-centric. This module
fills the Linux gap by inspecting the classic *nix persistence surfaces that
DFIR triage collects from a mounted image or a live-response bundle:

- **systemd units** with a suspicious ``ExecStart`` (reverse shells, netcat
  ``-e``, execution from ``/tmp`` or ``/dev/shm``, ``base64|eval`` decoding,
  ``curl|wget`` piped to a shell). MITRE ATT&CK **T1543.002** (Create or Modify
  System Process: Systemd Service).
- **cron entries** invoking the same suspicious-command table. MITRE ATT&CK
  **T1053.003** (Scheduled Task/Job: Cron).
- a non-empty ``/etc/ld.so.preload`` pointing at a shared object outside the
  standard system library paths. MITRE ATT&CK **T1574.006** (Hijack Execution
  Flow: Dynamic Linker Hijacking).
- **sudoers** lines granting ``NOPASSWD: ALL`` to a non-system principal, or a
  ``NOPASSWD`` command living in a world-writable path. MITRE ATT&CK
  **T1548.003** (Abuse Elevation Control Mechanism: Sudo and Sudo Caching).
- **bashrc / profile** lines containing a reverse shell or ``curl|sh`` payload.
  MITRE ATT&CK **T1546.004** (Event Triggered Execution: Unix Shell
  Configuration Modification).

All detectors share a single :data:`_SUSPICIOUS_CMD` regex table so the notion
of "a suspicious command" stays consistent across surfaces. Input dicts are
never mutated.
"""

from __future__ import annotations

import re
from typing import Any, Optional

from ..findings import Finding, FindingCategory

# --- shared suspicious-command table -----------------------------------------

# One table, reused by systemd / cron / bashrc. Each pattern captures a distinct
# offensive shape a defender expects to see in a persistence payload. Compiled
# case-insensitively; matched against the raw command text.
_SUSPICIOUS_CMD: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(r"\bbash\s+-i\b", re.IGNORECASE),
        "interactive bash reverse shell (bash -i)",
    ),
    (re.compile(r"/dev/tcp/", re.IGNORECASE), "bash /dev/tcp network redirection"),
    (
        re.compile(r"\bnc\b[^\n]*\s-e\b", re.IGNORECASE),
        "netcat with -e command execution",
    ),
    (
        re.compile(r"\bncat\b[^\n]*\s-e\b", re.IGNORECASE),
        "ncat with -e command execution",
    ),
    (
        re.compile(r"(?:/tmp/|/dev/shm/)\S*", re.IGNORECASE),
        "execution from /tmp or /dev/shm",
    ),
    (re.compile(r"base64\s+(?:-d|--decode)", re.IGNORECASE), "base64-decoded payload"),
    (re.compile(r"\beval\b", re.IGNORECASE), "eval of dynamic content"),
    (
        re.compile(r"\b(?:curl|wget)\b[^\n|]*\|\s*(?:ba)?sh\b", re.IGNORECASE),
        "curl/wget piped to a shell",
    ),
)

# Directories the dynamic linker legitimately loads shared objects from. An
# ld.so.preload entry outside every one of these is treated as hijacking.
_STANDARD_LIB_PREFIXES: tuple[str, ...] = (
    "/lib/",
    "/lib32/",
    "/lib64/",
    "/libx32/",
    "/usr/lib/",
    "/usr/lib32/",
    "/usr/lib64/",
    "/usr/libx32/",
    "/usr/local/lib/",
)

# Directories any local user can write to; a NOPASSWD grant on a command here is
# a trivial privilege-escalation backdoor.
_WORLD_WRITABLE_PREFIXES: tuple[str, ...] = (
    "/tmp/",
    "/dev/shm/",
    "/var/tmp/",
)

# sudoers principals that are expected to hold broad rights. A NOPASSWD:ALL grant
# to any principal outside this set is treated as a backdoor.
_SYSTEM_SUDO_PRINCIPALS: frozenset[str] = frozenset(
    {"root", "%admin", "%sudo", "%wheel"}
)

_NOPASSWD_ALL = re.compile(r"NOPASSWD:\s*ALL\b", re.IGNORECASE)
_NOPASSWD_CMD = re.compile(r"NOPASSWD:\s*(?P<cmd>\S+)", re.IGNORECASE)


def _match_suspicious(command: str) -> Optional[str]:
    """Return the reason string for the first suspicious pattern that matches.

    Args:
        command: Raw command text to test.

    Returns:
        The human-readable reason for the first matching pattern, or ``None``
        when the command matches nothing in the shared table.
    """
    for pattern, reason in _SUSPICIOUS_CMD:
        if pattern.search(command):
            return reason
    return None


class LinuxPersistenceDetector:
    """Detects Linux persistence mechanisms from collected artifacts.

    The detector is stateless; :meth:`analyze` is a pure function of its input
    and never mutates the artifacts dict it is given.
    """

    def analyze(self, artifacts: dict[str, Any]) -> list[Finding]:
        """Scan Linux persistence artifacts and return case-agnostic findings.

        Args:
            artifacts: Mapping that may contain any of ``systemd_units``,
                ``cron_entries``, ``ld_preload``, ``sudoers`` and
                ``bashrc_entries``. Missing keys are treated as empty.

        Returns:
            A list of :class:`Finding` objects, one per detected persistence
            mechanism, all tagged :attr:`FindingCategory.PERSISTENCE`.
        """
        findings: list[Finding] = []
        findings.extend(self._analyze_systemd(artifacts.get("systemd_units") or []))
        findings.extend(self._analyze_cron(artifacts.get("cron_entries") or []))
        findings.extend(self._analyze_ld_preload(artifacts.get("ld_preload")))
        findings.extend(self._analyze_sudoers(artifacts.get("sudoers") or []))
        findings.extend(self._analyze_bashrc(artifacts.get("bashrc_entries") or []))
        return findings

    # --- systemd -------------------------------------------------------------

    def _analyze_systemd(self, units: list[dict[str, Any]]) -> list[Finding]:
        """Flag systemd units whose ExecStart is a suspicious command."""
        findings: list[Finding] = []
        for unit in units:
            command = str(unit.get("exec_start") or unit.get("content") or "")
            reason = _match_suspicious(command)
            if reason is None:
                continue
            path = str(unit.get("path", "(unknown unit)"))
            findings.append(
                Finding(
                    title=f"Malicious systemd unit: {path}",
                    description=(
                        f"systemd unit '{path}' has a suspicious ExecStart "
                        f"({reason}): {command!r}."
                    ),
                    finding_type="behavior",
                    severity="critical",
                    category=FindingCategory.PERSISTENCE,
                    evidence={
                        "path": path,
                        "reason": reason,
                        "matched": command,
                        "mitre_technique": "T1543.002",
                    },
                    reasoning_chain=[
                        f"systemd unit {path} runs {command!r} at boot/activation.",
                        f"Command matches a suspicious shape: {reason}.",
                        "Persistent code execution via a systemd service (T1543.002).",
                    ],
                    artifact_sources=["systemd"],
                )
            )
        return findings

    # --- cron ----------------------------------------------------------------

    def _analyze_cron(self, entries: list[dict[str, Any]]) -> list[Finding]:
        """Flag cron lines invoking a suspicious command."""
        findings: list[Finding] = []
        for entry in entries:
            line = str(entry.get("line") or "")
            reason = _match_suspicious(line)
            if reason is None:
                continue
            path = str(entry.get("path", "(unknown cron)"))
            findings.append(
                Finding(
                    title=f"Malicious cron entry in {path}",
                    description=(
                        f"cron file '{path}' schedules a suspicious command "
                        f"({reason}): {line!r}."
                    ),
                    finding_type="behavior",
                    severity="high",
                    category=FindingCategory.PERSISTENCE,
                    evidence={
                        "path": path,
                        "reason": reason,
                        "matched": line,
                        "mitre_technique": "T1053.003",
                    },
                    reasoning_chain=[
                        f"cron file {path} runs {line!r} on a schedule.",
                        f"Command matches a suspicious shape: {reason}.",
                        "Scheduled persistence via cron (T1053.003).",
                    ],
                    artifact_sources=["cron"],
                )
            )
        return findings

    # --- ld.so.preload -------------------------------------------------------

    def _analyze_ld_preload(self, content: Optional[str]) -> list[Finding]:
        """Flag ld.so.preload objects outside the standard library paths."""
        if not content:
            return []
        offenders = [
            token
            for token in content.split()
            if token and not any(token.startswith(p) for p in _STANDARD_LIB_PREFIXES)
        ]
        if not offenders:
            return []
        return [
            Finding(
                title="Dynamic linker hijack via /etc/ld.so.preload",
                description=(
                    "/etc/ld.so.preload force-loads shared object(s) outside the "
                    f"standard library paths: {', '.join(offenders)}."
                ),
                finding_type="indicator",
                severity="critical",
                category=FindingCategory.PERSISTENCE,
                evidence={
                    "path": "/etc/ld.so.preload",
                    "reason": "preloaded object outside standard lib paths",
                    "matched": offenders,
                    "mitre_technique": "T1574.006",
                },
                reasoning_chain=[
                    "/etc/ld.so.preload is non-empty.",
                    f"It preloads {offenders!r}, none under a standard lib path.",
                    "Every dynamically-linked process loads these objects "
                    "(T1574.006).",
                ],
                artifact_sources=["ld.so.preload"],
            )
        ]

    # --- sudoers -------------------------------------------------------------

    def _analyze_sudoers(self, entries: list[dict[str, Any]]) -> list[Finding]:
        """Flag sudoers lines that hand out a NOPASSWD backdoor."""
        findings: list[Finding] = []
        for entry in entries:
            line = str(entry.get("line") or "").strip()
            if not line or line.startswith("#") or line.startswith("Defaults"):
                continue
            reason = self._sudoers_reason(line)
            if reason is None:
                continue
            path = str(entry.get("path", "(unknown sudoers)"))
            findings.append(
                Finding(
                    title=f"Sudoers privilege backdoor in {path}",
                    description=(
                        f"sudoers file '{path}' contains a risky grant "
                        f"({reason}): {line!r}."
                    ),
                    finding_type="indicator",
                    severity="high",
                    category=FindingCategory.PERSISTENCE,
                    evidence={
                        "path": path,
                        "reason": reason,
                        "matched": line,
                        "mitre_technique": "T1548.003",
                    },
                    reasoning_chain=[
                        f"sudoers file {path} contains {line!r}.",
                        reason,
                        "Passwordless privilege escalation persistence " "(T1548.003).",
                    ],
                    artifact_sources=["sudoers"],
                )
            )
        return findings

    @staticmethod
    def _sudoers_reason(line: str) -> Optional[str]:
        """Return why a sudoers line is risky, or ``None`` when it is benign."""
        principal = line.split(None, 1)[0]
        if _NOPASSWD_ALL.search(line):
            if principal not in _SYSTEM_SUDO_PRINCIPALS:
                return f"NOPASSWD:ALL granted to non-system principal '{principal}'"
            return None
        command_match = _NOPASSWD_CMD.search(line)
        if command_match:
            command = command_match.group("cmd")
            if any(command.startswith(p) for p in _WORLD_WRITABLE_PREFIXES):
                return f"NOPASSWD command in world-writable path '{command}'"
        return None

    # --- bashrc --------------------------------------------------------------

    def _analyze_bashrc(self, entries: list[dict[str, Any]]) -> list[Finding]:
        """Flag shell-init lines carrying a reverse shell or curl|sh payload."""
        findings: list[Finding] = []
        for entry in entries:
            line = str(entry.get("line") or "")
            reason = _match_suspicious(line)
            if reason is None:
                continue
            path = str(entry.get("path", "(unknown shell init)"))
            findings.append(
                Finding(
                    title=f"Malicious shell-init entry in {path}",
                    description=(
                        f"shell init file '{path}' runs a suspicious command "
                        f"on every interactive shell ({reason}): {line!r}."
                    ),
                    finding_type="behavior",
                    severity="high",
                    category=FindingCategory.PERSISTENCE,
                    evidence={
                        "path": path,
                        "reason": reason,
                        "matched": line,
                        "mitre_technique": "T1546.004",
                    },
                    reasoning_chain=[
                        f"shell init file {path} runs {line!r} on shell start.",
                        f"Command matches a suspicious shape: {reason}.",
                        "Persistence via Unix shell configuration (T1546.004).",
                    ],
                    artifact_sources=["shell_init"],
                )
            )
        return findings
