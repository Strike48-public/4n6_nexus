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

- ``DATA_EXFILTRATION`` / ``LATERAL_MOVEMENT`` / ``PROCESS_INJECTION``
  for netscan rows: a LOLBAS process with an ESTABLISHED connection to
  a routable foreign IP is a canonical reverse-shell / C2 signal
  (T1071); the same process talking to an RFC1918 peer on a SMB/WinRM/
  RPC port is lateral movement (T1021); and a socket with no owning PID
  is kernel-side / hidden activity that pairs with a T1014 rootkit
  signal. netscan does NOT feed ``BeaconingDetector`` because netscan
  is a point-in-time snapshot — there are no inter-event intervals to
  compute coefficient of variation from.

The detector never shells out — it consumes pre-run plugin rows. That
lets callers choose when to pay the 30-60s Vol3 symbolization cost
(e.g. once per scenario rather than once per detector).
"""

from __future__ import annotations

import ipaddress
import re
from typing import Iterable, Optional

from ..findings import FindingCategory
from ..memory.volatility_runner import (
    CommandLineRow,
    InjectionRow,
    NetworkRow,
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

# Reverse-shell / C2 destination ports commonly seen in offensive tooling.
# Metasploit defaults (4444, 4445), Cobalt Strike defaults (50050 is
# attacker-side), common handler listens (1337, 31337), and Empire/Sliver
# defaults. The list is tuned to stay tight — broader port lists (all
# unassigned high ports) would drown legitimate ephemeral-client traffic.
_REVERSE_SHELL_PORTS: frozenset[int] = frozenset(
    {
        1337,
        4040,  # ngrok default; not offensive itself but routinely used
        4444,  # Metasploit default
        4445,  # Metasploit alt
        5555,
        8081,
        9001,  # Tor relay
        9050,  # Tor SOCKS
        31337,
    }
)

# RFC1918 networks — connections here are "inside the enterprise" and
# indicate lateral movement rather than exfil when paired with a LOLBAS
# process. Matched via ipaddress.ip_address().is_private, which also
# covers link-local, loopback, and unique-local (IPv6 fc00::/7). We
# exclude loopback separately because same-host IPC is never a finding.
_SMB_WINRM_RPC_PORTS: frozenset[int] = frozenset(
    {
        135,  # RPC endpoint mapper
        139,  # NetBIOS session
        445,  # SMB
        5985,  # WinRM HTTP
        5986,  # WinRM HTTPS
        3389,  # RDP
    }
)


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
        netscan: Optional[Iterable[NetworkRow]] = None,
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
        findings.extend(self._analyze_netscan(netscan or ()))
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

    # --- netscan (suspicious sockets) -------------------------------------

    def _analyze_netscan(self, rows: Iterable[NetworkRow]) -> list[Finding]:
        findings: list[Finding] = []
        for row in rows:
            finding = self._classify_netscan_row(row)
            if finding is not None:
                findings.append(finding)
        return findings

    def _classify_netscan_row(self, row: NetworkRow) -> Optional[Finding]:
        # Unowned sockets — kernel-side or hidden process — fire first
        # regardless of destination. This is the T1014 adjunct to the
        # pslist/psscan divergence finding.
        if row.pid is None and not (row.owner or "").strip():
            if row.foreign_addr and not _is_loopback(row.foreign_addr):
                return self._build_unowned_socket_finding(row)
            return None

        # From here on we need an established connection to a remote peer.
        if not row.foreign_addr:
            return None
        if _is_loopback(row.foreign_addr):
            return None
        # LISTENING sockets have no committed remote endpoint; skip them
        # to avoid flagging every service-waiting-for-clients as suspicious.
        state = (row.state or "").upper()
        if state in {"LISTENING", "LISTEN", "CLOSED"}:
            return None

        basename = _normalize_basename(row.owner or "")
        is_lolbas = basename in _LOLBAS_LAUNCHERS
        if not is_lolbas:
            # We only alert on LOLBAS-owned sockets today. A fuller
            # implementation would also flag unknown/unsigned binaries
            # with network activity, but that requires a signer oracle
            # we do not have in-process.
            return None

        is_private = _is_rfc1918(row.foreign_addr)
        port = row.foreign_port or 0

        if is_private:
            return self._build_lateral_movement_finding(row, basename, port)
        return self._build_exfil_finding(row, basename, port)

    def _build_unowned_socket_finding(self, row: NetworkRow) -> Finding:
        return Finding(
            title=(
                f"Unowned network socket to {row.foreign_addr}:{row.foreign_port}"
            ),
            description=(
                "Volatility netscan reports an ESTABLISHED connection with "
                "no owning PID or process name. Kernel-side sockets exist "
                "legitimately (e.g. TCP offload engines, some IPv6 stacks) "
                "but an unowned socket to a routable foreign address is a "
                "classic rootkit signal — the owning process was unlinked "
                "from the process list before the snapshot."
            ),
            finding_type="behavior",
            severity="high",
            category=FindingCategory.PROCESS_INJECTION,
            evidence={
                "protocol": row.protocol,
                "local_addr": row.local_addr,
                "local_port": row.local_port,
                "foreign_addr": row.foreign_addr,
                "foreign_port": row.foreign_port,
                "state": row.state,
                "mitre_attack": ["T1014"],
            },
            confidence=0.65,
            confidence_label="Medium",
            reasoning_chain=[
                "netscan reports a socket with pid=None and no owner.",
                "Unowned sockets to routable foreign addresses are a "
                "T1014 rootkit adjunct — the owning process has been "
                "unlinked from the process list.",
                "False-positive surface: kernel-mode drivers legitimately "
                "hold sockets; on Windows these typically loop back or "
                "stay in LISTENING state, not ESTABLISHED to external IPs.",
            ],
            artifact_sources=["memory"],
        )

    def _build_lateral_movement_finding(
        self, row: NetworkRow, basename: str, port: int
    ) -> Finding:
        is_lm_port = port in _SMB_WINRM_RPC_PORTS
        reasons = [
            f"LOLBAS process '{basename}' owns the socket",
            f"Foreign address {row.foreign_addr} is RFC1918 (internal peer)",
        ]
        if is_lm_port:
            reasons.append(
                f"Destination port {port} is SMB/WinRM/RPC — canonical "
                "lateral-movement channel"
            )
            confidence, label, severity = 0.80, "High", "high"
        else:
            confidence, label, severity = 0.55, "Low", "medium"
        return Finding(
            title=(
                f"LOLBAS process to internal peer: PID {row.pid} "
                f"({row.owner}) -> {row.foreign_addr}:{port}"
            ),
            description=(
                f"Volatility netscan shows {row.owner} (PID {row.pid}) "
                f"connected to {row.foreign_addr}:{port}. A LOLBAS host "
                "talking to an RFC1918 peer is a lateral-movement "
                f"signal (MITRE T1021). Suspicious because: "
                f"{'; '.join(reasons)}."
            ),
            finding_type="behavior",
            severity=severity,
            category=FindingCategory.LATERAL_MOVEMENT,
            evidence={
                "pid": row.pid,
                "process": row.owner,
                "protocol": row.protocol,
                "local_addr": row.local_addr,
                "local_port": row.local_port,
                "foreign_addr": row.foreign_addr,
                "foreign_port": port,
                "state": row.state,
                "reasons": reasons,
                "mitre_attack": ["T1021"],
            },
            confidence=confidence,
            confidence_label=label,
            reasoning_chain=[
                f"PID {row.pid} ({row.owner}) holds a socket to "
                f"{row.foreign_addr}:{port}.",
                *reasons,
                "Remote Services abuse (MITRE T1021) is how operators "
                "pivot from initial foothold to additional hosts.",
            ],
            artifact_sources=["memory"],
        )

    def _build_exfil_finding(
        self, row: NetworkRow, basename: str, port: int
    ) -> Finding:
        is_reverse_shell_port = port in _REVERSE_SHELL_PORTS
        reasons = [
            f"LOLBAS process '{basename}' owns an external socket",
            f"Foreign address {row.foreign_addr} is publicly routable",
        ]
        if is_reverse_shell_port:
            reasons.append(
                f"Destination port {port} is a known reverse-shell / C2 "
                "default"
            )
            confidence, label, severity = 0.80, "High", "high"
        else:
            confidence, label, severity = 0.55, "Low", "medium"
        return Finding(
            title=(
                f"LOLBAS external connection: PID {row.pid} "
                f"({row.owner}) -> {row.foreign_addr}:{port}"
            ),
            description=(
                f"Volatility netscan shows {row.owner} (PID {row.pid}) "
                f"connected to {row.foreign_addr}:{port}. A LOLBAS host "
                "holding a socket to a routable foreign address is a "
                "canonical reverse-shell / C2 signal (MITRE T1071). "
                f"Suspicious because: {'; '.join(reasons)}."
            ),
            finding_type="behavior",
            severity=severity,
            category=FindingCategory.DATA_EXFILTRATION,
            evidence={
                "pid": row.pid,
                "process": row.owner,
                "protocol": row.protocol,
                "local_addr": row.local_addr,
                "local_port": row.local_port,
                "foreign_addr": row.foreign_addr,
                "foreign_port": port,
                "state": row.state,
                "reasons": reasons,
                "mitre_attack": ["T1071"],
            },
            confidence=confidence,
            confidence_label=label,
            reasoning_chain=[
                f"PID {row.pid} ({row.owner}) holds a socket to "
                f"{row.foreign_addr}:{port}.",
                *reasons,
                "Application-Layer Protocol abuse (MITRE T1071) is the "
                "usual channel for reverse shells and beaconing.",
            ],
            artifact_sources=["memory"],
        )


# --- module-local helpers -----------------------------------------------

def _normalize_basename(process: str) -> str:
    basename = process.strip().lower()
    if "\\" in basename:
        basename = basename.rsplit("\\", 1)[-1]
    if "/" in basename:
        basename = basename.rsplit("/", 1)[-1]
    return basename


_RFC1918_NETWORKS: tuple[ipaddress.IPv4Network, ...] = (
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
)


def _is_rfc1918(addr: str) -> bool:
    # We check explicit RFC1918 ranges rather than ``ipaddress.is_private``
    # because is_private also returns True for documentation ranges
    # (TEST-NET-1/2/3 — 192.0.2/24, 198.51.100/24, 203.0.113/24). Those
    # show up in PCAPs / scenarios as "external" by convention even
    # though is_private flags them, so treating them as lateral-movement
    # targets would mis-classify every documented test fixture.
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    if not isinstance(ip, ipaddress.IPv4Address):
        # IPv6 ULA (fc00::/7) is genuinely an internal address. IPv6 link-
        # local (fe80::/10) is link-scoped and never routes — skip both
        # as lateral-movement signals for now until we have scenario
        # coverage that justifies a specific policy.
        return False
    return any(ip in net for net in _RFC1918_NETWORKS)


def _is_loopback(addr: str) -> bool:
    try:
        return ipaddress.ip_address(addr).is_loopback
    except ValueError:
        return False
