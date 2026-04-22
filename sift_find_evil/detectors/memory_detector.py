"""MemoryDetector — turn Volatility 3 plugin output into Findings.

Consumes the typed dataclasses produced by ``memory.VolatilityRunner`` and
emits case-agnostic findings. Three finding classes today:

- ``PROCESS_INJECTION`` for malfind hits with RWX VAD protection. Unbacked
  RWX private memory is the canonical signal for shellcode / reflective
  DLL injection (MITRE T1055). We do NOT flag every malfind row — some
  modern JITs legitimately map RWX pages — so the confidence is medium
  and the reasoning chain calls out the false-positive surface.

- ``PROCESS_INJECTION`` (secondary class) for pslist/psscan divergence.
  A process that appears in psscan but not pslist is a classic hidden-
  process signal — unlinking from PsActiveProcessHead is DKOM (Direct
  Kernel Object Manipulation), which maps to MITRE T1014 (Rootkit). We
  do NOT tag T1620 here (that covers reflective in-memory code loading,
  a different behavior). System Idle / terminated processes can
  legitimately desync, so we exclude known-good PIDs and cap confidence
  at medium until the tuning tickets land.

- ``PERSISTENCE`` for cmdline entries whose argv fires the same
  LOLBAS-launcher / hidden-powershell-flags heuristics as
  ``RegistryDetector``. We reuse the lower-level matchers rather than
  duplicating regexes so a rule change in one place flows to both.

The detector never shells out — it consumes pre-run plugin rows. That
lets callers choose when to pay the 30-60s Vol3 symbolization cost
(e.g. once per scenario rather than once per detector).
"""

from __future__ import annotations

import re
from typing import Iterable, Optional

from ..findings import FindingCategory
from ..memory.volatility_runner import (
    CommandLineRow,
    InjectionRow,
    ProcessRow,
)
from ..self_correction.engine import Finding

# PIDs that routinely appear in psscan but not pslist because they have
# already terminated / are synthetic. Keeping them out of the hidden-
# process finding set avoids drowning real leads in noise.
_PSSCAN_ONLY_WHITELIST: frozenset[int] = frozenset({0, 4})

# VAD protection values that indicate executable+writable memory — the
# hallmark of shellcode / unbacked injection. Volatility renders these as
# strings; we normalize to lowercase for case-insensitive matching.
_RWX_PROTECTIONS: frozenset[str] = frozenset(
    {
        "page_execute_readwrite",
        "page_execute_writecopy",
    }
)

# LOLBAS launcher basenames — shared in spirit with RegistryDetector but
# kept local so detectors stay decoupled. If we grow a third consumer we
# will promote this to a shared module.
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

_HIDDEN_POWERSHELL_FLAGS = re.compile(
    r"(?:^|\s)-(?:encodedcommand|enc|e|w\s+hidden|"
    r"windowstyle\s+hidden|noprofile|nop|"
    r"executionpolicy\s+bypass|ep\s+bypass)\b",
    re.IGNORECASE,
)

_MAX_COMMAND_LENGTH = 8192


class MemoryDetector:
    """Convert Volatility plugin rows into Findings.

    The detector is stateless beyond its configuration; each ``analyze``
    call builds a fresh finding list so detectors can be reused across
    scenarios without leaking state.
    """

    def __init__(
        self,
        *,
        psscan_only_whitelist: frozenset[int] = _PSSCAN_ONLY_WHITELIST,
    ):
        self._whitelist = psscan_only_whitelist

    def analyze(
        self,
        *,
        pslist: Optional[Iterable[ProcessRow]] = None,
        psscan: Optional[Iterable[ProcessRow]] = None,
        malfind: Optional[Iterable[InjectionRow]] = None,
        cmdline: Optional[Iterable[CommandLineRow]] = None,
    ) -> list[Finding]:
        """Return findings derived from any supplied plugin streams.

        Missing streams are silently skipped — callers that have only
        run pslist+psscan still get hidden-process findings; callers
        that add malfind get injection findings on top. The detector
        does not require the full plugin set because Volatility runs
        can take minutes per plugin and operators sometimes rerun a
        subset after tuning.
        """
        findings: list[Finding] = []
        findings.extend(self._analyze_malfind(malfind or ()))
        findings.extend(self._analyze_hidden_processes(pslist, psscan))
        findings.extend(self._analyze_cmdline(cmdline or ()))
        return findings

    # --- malfind (unbacked RWX memory) -------------------------------------

    def _analyze_malfind(self, rows: Iterable[InjectionRow]) -> list[Finding]:
        findings: list[Finding] = []
        for row in rows:
            protection = (row.protection or "").strip().lower()
            is_rwx = protection in _RWX_PROTECTIONS
            # malfind also fires on suspicious non-RWX regions (e.g. MZ
            # headers in private memory); we only flag the strongest
            # signal to keep per-image finding counts manageable.
            if not is_rwx:
                continue
            findings.append(self._build_malfind_finding(row))
        return findings

    def _build_malfind_finding(self, row: InjectionRow) -> Finding:
        # MITRE T1055 (Process Injection) is the canonical mapping; we
        # cite the sub-technique only when we have evidence of reflective
        # loading (PE header in private memory), which malfind doesn't
        # distinguish reliably here — leave sub-technique classification
        # to downstream triage.
        confidence = 0.70
        return Finding(
            title=(
                f"Unbacked RWX memory in PID {row.pid} ({row.process})"
            ),
            description=(
                f"Volatility malfind reports {row.protection} VAD in "
                f"PID {row.pid} ({row.process}) at VPN "
                f"{row.start_vpn}-{row.end_vpn}. Unbacked executable+"
                "writable private memory is the canonical signal for "
                "shellcode injection / reflective loading. Legitimate "
                "JITs (modern browsers, .NET CLR) also map RWX pages, "
                "so this finding requires triage before escalation."
            ),
            finding_type="behavior",
            severity="high",
            category=FindingCategory.PROCESS_INJECTION,
            evidence={
                "pid": row.pid,
                "process": row.process,
                "protection": row.protection,
                "tag": row.tag,
                "start_vpn": row.start_vpn,
                "end_vpn": row.end_vpn,
                "commit_charge": row.commit_charge,
                "private_memory": row.private_memory,
                "mitre_attack": ["T1055"],
            },
            confidence=confidence,
            confidence_label="Medium",
            reasoning_chain=[
                f"malfind identified VAD with protection={row.protection}.",
                "Unbacked RWX private memory is the canonical signal for "
                "injected shellcode (MITRE T1055).",
                "False-positive surface: JIT compilers (V8, SpiderMonkey, "
                ".NET CLR) legitimately map RWX pages; confirm the owning "
                "process is not a known JIT host before escalation.",
            ],
            artifact_sources=["memory"],
        )

    # --- pslist / psscan divergence (hidden processes) --------------------

    def _analyze_hidden_processes(
        self,
        pslist: Optional[Iterable[ProcessRow]],
        psscan: Optional[Iterable[ProcessRow]],
    ) -> list[Finding]:
        if pslist is None or psscan is None:
            return []
        pslist_pids = {row.pid for row in pslist}
        psscan_rows = list(psscan)
        findings: list[Finding] = []
        for row in psscan_rows:
            if row.pid in pslist_pids:
                continue
            if row.pid in self._whitelist:
                continue
            # A process that has already exited legitimately shows up in
            # psscan but not pslist. Skip it to avoid flooding findings
            # with benign terminations.
            if row.exit_time:
                continue
            findings.append(self._build_hidden_process_finding(row))
        return findings

    def _build_hidden_process_finding(self, row: ProcessRow) -> Finding:
        confidence = 0.65
        return Finding(
            title=(
                f"Hidden process: PID {row.pid} ({row.name}) in psscan but not pslist"
            ),
            description=(
                f"Volatility psscan found PID {row.pid} ({row.name}) "
                "with no corresponding pslist entry and no exit time. "
                "Processes unlinked from the active process list are a "
                "classic rootkit / DKOM signal (MITRE T1014), though "
                "System (PID 4) and Idle (PID 0) routinely differ and "
                "some rootkit-hunting tools themselves trigger this."
            ),
            finding_type="behavior",
            severity="high",
            category=FindingCategory.PROCESS_INJECTION,
            evidence={
                "pid": row.pid,
                "ppid": row.ppid,
                "process": row.name,
                "create_time": row.create_time,
                "source": "psscan_without_pslist",
                "mitre_attack": ["T1014"],
            },
            confidence=confidence,
            confidence_label="Medium",
            reasoning_chain=[
                f"psscan reports PID {row.pid} ({row.name}); pslist does not.",
                "Active processes missing from the doubly-linked process "
                "list are a classic DKOM (Direct Kernel Object Manipulation) "
                "signal used by rootkits to hide malware (MITRE T1014).",
                "False-positive surface: terminated-before-pslist-pass "
                "processes, System/Idle PIDs, and some EDR tools.",
            ],
            artifact_sources=["memory"],
        )

    # --- cmdline (LOLBAS + hidden-flag heuristics) ------------------------

    def _analyze_cmdline(self, rows: Iterable[CommandLineRow]) -> list[Finding]:
        findings: list[Finding] = []
        for row in rows:
            if row.args is None:
                continue
            reasons = self._cmdline_reasons(row.process, row.args)
            if not reasons:
                continue
            findings.append(self._build_cmdline_finding(row, reasons))
        return findings

    def _cmdline_reasons(self, process: str, args: str) -> list[str]:
        reasons: list[str] = []
        basename = process.strip().lower()
        # Volatility reports the raw image name; normalize to basename
        # so "System32\\powershell.exe" and "powershell.exe" both hit.
        if "\\" in basename:
            basename = basename.rsplit("\\", 1)[-1]
        if "/" in basename:
            basename = basename.rsplit("/", 1)[-1]

        if basename in _LOLBAS_LAUNCHERS:
            reasons.append(f"Process '{basename}' is a LOLBAS/script host")

        if len(args) <= _MAX_COMMAND_LENGTH and _HIDDEN_POWERSHELL_FLAGS.search(args):
            reasons.append("Command line uses hidden/encoded/bypass launcher flags")
        return reasons

    def _build_cmdline_finding(
        self, row: CommandLineRow, reasons: list[str]
    ) -> Finding:
        # Single-reason LOLBAS match is generic (many admin scripts use
        # powershell.exe). Two-reason hits — LOLBAS + hidden flags — are
        # persistence-class signals.
        if len(reasons) >= 2:
            confidence, label, severity = 0.80, "High", "high"
        else:
            confidence, label, severity = 0.55, "Low", "medium"
        return Finding(
            title=(
                f"Suspicious command line: PID {row.pid} ({row.process})"
            ),
            description=(
                f"Volatility cmdline shows PID {row.pid} ({row.process}) "
                f"running '{row.args}'. Suspicious because: "
                f"{'; '.join(reasons)}."
            ),
            finding_type="behavior",
            severity=severity,
            category=FindingCategory.PERSISTENCE,
            evidence={
                "pid": row.pid,
                "process": row.process,
                "args": row.args,
                "reasons": reasons,
                "mitre_attack": ["T1059"],
            },
            confidence=confidence,
            confidence_label=label,
            reasoning_chain=[
                f"PID {row.pid} invoked {row.process}.",
                *reasons,
                "Command-interpreter abuse maps to MITRE T1059; combined "
                "with hidden flags it is a strong persistence / execution "
                "signal.",
            ],
            artifact_sources=["memory"],
        )
