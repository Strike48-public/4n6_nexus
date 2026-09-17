"""Linux history-based execution detector (SFE-jdii).

The engine's execution detectors are Windows/memory-centric. This module fills
the Linux gap by inspecting recorded shell history (from
``parsers.linux_history.parse_shell_history``) for **suspicious command
execution**: a command line matching an offensive shape (reverse shell,
``curl|sh`` download cradle, ``base64``-decoded payload, execution from
``/tmp``/``/dev/shm``, netcat ``-e``).

A malicious command preserved in ``~/.bash_history`` / ``.zsh_history`` is
direct evidence the operator (or an intruder using the account) ran it -- MITRE
ATT&CK **T1059.004** (Command and Scripting Interpreter: Unix Shell). The
offensive shapes come from the shared
:func:`~sift_find_evil.detectors._suspicious_cmd.match_suspicious` matcher, so
"a suspicious command" is defined once and reused across the Linux surfaces.

**Precision on the /tmp shape (SFE-l3ep).** This surface passes
``interactive=True`` to the shared matcher. Interactive shell history is far
noisier than a persistence directive -- a real operator constantly reads and
edits files under ``/tmp``/``/dev/shm`` (``cat /tmp/report.txt``,
``ls -la /tmp/``) -- so on this surface the world-writable-path shape fires
only when the path is in an *execution or staging* position (run as a program,
interpreted by a shell, made executable, or written by a downloader), not for a
bare read or navigation reference. The path definition itself stays in the
single shared module (:mod:`._suspicious_cmd`); only the required *position*
differs from the persistence directive surfaces, so the two cannot drift on
what counts as a world-writable path.

The detector is stateless and never mutates the artifacts dict it is given.
"""

from __future__ import annotations

from typing import Any

from ..findings import Finding, FindingCategory
from ._suspicious_cmd import match_suspicious


class LinuxExecutionDetector:
    """Detects suspicious command execution recorded in shell history.

    The detector is stateless; :meth:`analyze` is a pure function of its input
    and never mutates the artifacts dict it is given.
    """

    def analyze(self, artifacts: dict[str, Any]) -> list[Finding]:
        """Scan recorded shell history and return execution findings.

        Args:
            artifacts: Mapping that may contain ``shell_history`` -- a list of
                normalized command entries (see
                :func:`~sift_find_evil.parsers.linux_history.parse_shell_history`),
                each a dict with ``"path"`` and ``"command"``. A missing key is
                treated as an empty list.

        Returns:
            One :class:`Finding` per history line whose command matches a shape
            in the shared suspicious-command table, tagged
            :attr:`FindingCategory.EXECUTION`.
        """
        entries = artifacts.get("shell_history") or []
        findings: list[Finding] = []
        for entry in entries:
            command = str(entry.get("command") or "")
            reason = match_suspicious(command, interactive=True)
            if reason is None:
                continue
            path = str(entry.get("path", "(unknown history)"))
            findings.append(self._build_finding(path, command, reason))
        return findings

    @staticmethod
    def _build_finding(path: str, command: str, reason: str) -> Finding:
        """Build the execution finding for one suspicious history command."""
        return Finding(
            title=f"Suspicious command in shell history: {path}",
            description=(
                f"shell history '{path}' records a suspicious command "
                f"({reason}): {command!r}."
            ),
            finding_type="behavior",
            severity="high",
            category=FindingCategory.EXECUTION,
            evidence={
                "path": path,
                "reason": reason,
                "matched": command,
                "mitre_technique": "T1059.004",
            },
            reasoning_chain=[
                f"shell history {path} records the command {command!r}.",
                f"Command matches a suspicious shape: {reason}.",
                "Direct evidence of malicious command execution via a Unix "
                "shell (T1059.004).",
            ],
            artifact_sources=["bash_history"],
        )
