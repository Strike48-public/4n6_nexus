"""Lateral-movement detector — cross-host authentication heuristics.

Promotes the SFE-e3g APT logon-graph analysis (``analysis/apt_logon_graph.py``,
validated against the real SANS SRL-2015 corpus: 281,829 4624/4625/4648/4672
events across 7 hosts) from a one-off analysis script into an in-engine
detector with TDD coverage.

It consumes parsed Windows Security ``EventLogEntry`` rows (EvtxECmd output) and
emits :class:`Finding` objects in the ``LATERAL_MOVEMENT`` category for four
high-signal, low-FP authentication patterns:

1. **Failed-logon spike** (4625) per target account or source host — password
   spraying / brute force / disabled-account probing. MITRE T1110.
2. **Service-account remote-interactive logon** (4624, LogonType 10) — a service
   account (e.g. ``spsql``) logging on via RDP is credential abuse, not normal
   service behaviour. MITRE T1078.
3. **Admin-tier cross-host spread** — a single domain account authenticating to
   N or more distinct hosts (4624/4648), the operator's pivot footprint. MITRE
   T1021.
4. **Explicit-credential burst** (4648) of one account on a single host —
   runas / pass-the-hash. MITRE T1078.

Machine accounts (``HOST$``) and local/virtual session principals (DWM-*,
UMFD-*, ``NT AUTHORITY\\*``, font/window-manager hosts) are filtered as routine
noise, mirroring the analysis script that was validated on real evidence.
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from typing import Iterable, Optional

from ..findings import Finding, FindingCategory
from ..parsers.evtx_parser import EventLogEntry

# Authentication events this detector reasons over.
_FAILED_LOGON = 4625
_SUCCESS_LOGON = 4624
_EXPLICIT_CRED = 4648

# Windows logon types relevant to lateral movement.
_LOGON_TYPE_RDP = "10"  # RemoteInteractive (RDP)

# Regexes mirroring the EvtxECmd payload shapes the analysis script parsed.
_TARGET_RE = re.compile(r"Target:\s*(.+)", re.IGNORECASE)
_LOGON_TYPE_RE = re.compile(r"LogonType\s+(\d+)")
_IP_RE = re.compile(r"\(([\d.]+)\)")

# Detection thresholds. Conservative defaults chosen to stay below the routine
# domain-chatter floor seen in the real SRL-2015 corpus while still firing on
# the genuine spray/pivot/runas campaigns it contains.
DEFAULT_FAILED_LOGON_THRESHOLD = 20  # per account or per source host
DEFAULT_CROSS_HOST_THRESHOLD = 3  # distinct hosts one account touches
DEFAULT_EXPLICIT_CRED_THRESHOLD = 10  # 4648 of one account on one host

# Service-account name markers. Interactive/RDP logon by one of these is abuse.
_SERVICE_ACCOUNT_MARKERS = ("svc", "sql", "service", "iis", "backup", "sched")

# Well-known local / virtual session principals present on every Windows host.
# Never a cross-host pivot; filtered to keep the account-spread graph clean.
_LOCAL_SESSION_PREFIXES = (
    "window manager\\",
    "font driver host\\",
    "nt authority\\",
    "nt service\\",
    "iis apppool\\",
    "dwm-",
    "umfd-",
)


def _is_machine_account(account: str) -> bool:
    """Machine accounts end in ``$`` — routine domain chatter, not pivots."""
    return account.rstrip().endswith("$")


def _is_noise_principal(account: str) -> bool:
    """True for empty/local/virtual session principals that add only noise."""
    lowered = account.strip().lower()
    if not lowered or lowered in ("\\", ""):
        return True
    return any(lowered.startswith(p) for p in _LOCAL_SESSION_PREFIXES)


def _is_real_account(account: str) -> bool:
    """A domain/user account worth tracking (not a machine or noise principal)."""
    return (
        bool(account)
        and not _is_machine_account(account)
        and not _is_noise_principal(account)
    )


def _looks_like_service_account(account: str) -> bool:
    """Heuristic: does the account name read like a non-interactive service?"""
    # Compare on the bare sAMAccountName (strip DOMAIN\ prefix).
    name = account.split("\\")[-1].strip().lower()
    return any(marker in name for marker in _SERVICE_ACCOUNT_MARKERS)


def _target_account(entry: EventLogEntry) -> str:
    """Extract the target account from an EvtxECmd logon row."""
    match = _TARGET_RE.search(entry.payload_data1 or "")
    if match:
        return match.group(1).strip().strip("-").strip()
    return ""


def _logon_type(entry: EventLogEntry) -> str:
    """Extract the LogonType digit from the row's payload fields."""
    blob = " ".join(getattr(entry, f"payload_data{i}") or "" for i in range(1, 7))
    match = _LOGON_TYPE_RE.search(blob)
    return match.group(1) if match else ""


def _source_label(entry: EventLogEntry) -> str:
    """Human label for the logon source, from the RemoteHost column."""
    remote = (entry.remote_host or "").strip()
    if not remote:
        return ""
    host = remote.split("(")[0].strip().strip("-").strip()
    ip_match = _IP_RE.search(remote)
    ip = ip_match.group(1) if ip_match else ""
    if host and ip:
        return f"{host} ({ip})"
    return host or ip


class LateralMovementDetector:
    """Detects cross-host lateral movement from Windows Security logon events."""

    def __init__(
        self,
        *,
        failed_logon_threshold: int = DEFAULT_FAILED_LOGON_THRESHOLD,
        cross_host_threshold: int = DEFAULT_CROSS_HOST_THRESHOLD,
        explicit_cred_threshold: int = DEFAULT_EXPLICIT_CRED_THRESHOLD,
    ) -> None:
        # A threshold below 1 would fire on every account/source/host and is
        # almost certainly a misconfiguration, so reject it rather than flood
        # the operator with findings.
        for name, value in (
            ("failed_logon_threshold", failed_logon_threshold),
            ("cross_host_threshold", cross_host_threshold),
            ("explicit_cred_threshold", explicit_cred_threshold),
        ):
            if value < 1:
                raise ValueError(f"{name} must be >= 1, got {value}")
        self.failed_logon_threshold = failed_logon_threshold
        self.cross_host_threshold = cross_host_threshold
        self.explicit_cred_threshold = explicit_cred_threshold

    def analyze(
        self, event_logs: Optional[Iterable[EventLogEntry]] = None
    ) -> list[Finding]:
        """Return lateral-movement findings from Security logon events.

        Args:
            event_logs: Parsed ``EventLogEntry`` rows (any event IDs; the
                detector selects the authentication events it cares about).

        Returns:
            A list of :class:`Finding` objects, empty when nothing fires.
        """
        events = list(event_logs or [])
        if not events:
            return []

        findings: list[Finding] = []
        findings.extend(self._detect_failed_logon_spikes(events))
        findings.extend(self._detect_service_account_rdp(events))
        findings.extend(self._detect_cross_host_spread(events))
        findings.extend(self._detect_explicit_cred_bursts(events))
        return findings

    # --- Signal 1: failed-logon spikes (4625) -----------------------------
    def _detect_failed_logon_spikes(self, events: list[EventLogEntry]) -> list[Finding]:
        failed = [e for e in events if e.event_id == _FAILED_LOGON]
        if not failed:
            return []

        by_account: Counter[str] = Counter()
        for e in failed:
            acct = _target_account(e)
            if _is_real_account(acct):
                by_account[acct] += 1

        by_source: Counter[str] = Counter()
        for e in failed:
            src = _source_label(e)
            if src:
                by_source[src] += 1

        findings: list[Finding] = []
        for account, count in by_account.items():
            if count >= self.failed_logon_threshold:
                findings.append(self._failed_account_finding(account, count))
        for source, count in by_source.items():
            if count >= self.failed_logon_threshold:
                findings.append(self._failed_source_finding(source, count))
        return findings

    def _failed_account_finding(self, account: str, count: int) -> Finding:
        return Finding(
            title=f"Failed-logon spike against account '{account}'",
            description=(
                f"Account '{account}' accumulated {count} failed logons (4625), "
                f"at or above the {self.failed_logon_threshold}-event threshold. "
                "A burst of failures against one account is a password-spray or "
                "brute-force / disabled-account-probing signal (MITRE T1110)."
            ),
            finding_type="behavior",
            severity="high",
            category=FindingCategory.LATERAL_MOVEMENT,
            evidence={
                "signal": "failed_logon_spike",
                "pivot": "account",
                "account": account,
                "failed_count": count,
                "threshold": self.failed_logon_threshold,
                "mitre": "T1110",
            },
            confidence=0.80,
            confidence_label="High",
            reasoning_chain=[
                f"{count} failed logons (4625) target account '{account}'.",
                f"That meets the spike threshold of {self.failed_logon_threshold}.",
                "Concentrated failures against one account indicate brute force "
                "or password spraying (MITRE T1110).",
            ],
            artifact_sources=["evtx"],
        )

    def _failed_source_finding(self, source: str, count: int) -> Finding:
        return Finding(
            title=f"Failed-logon spike from source {source}",
            description=(
                f"Source {source} generated {count} failed logons (4625), at or "
                f"above the {self.failed_logon_threshold}-event threshold. A single "
                "source driving many authentication failures is a brute-force or "
                "credential-stuffing origin (MITRE T1110)."
            ),
            finding_type="behavior",
            severity="high",
            category=FindingCategory.LATERAL_MOVEMENT,
            evidence={
                "signal": "failed_logon_spike",
                "pivot": "source",
                "source": source,
                "failed_count": count,
                "threshold": self.failed_logon_threshold,
                "mitre": "T1110",
            },
            confidence=0.80,
            confidence_label="High",
            reasoning_chain=[
                f"{count} failed logons (4625) originate from {source}.",
                f"That meets the spike threshold of {self.failed_logon_threshold}.",
                "A single high-volume source is a brute-force origin (T1110).",
            ],
            artifact_sources=["evtx"],
        )

    # --- Signal 2: service-account RDP logon (4624, type 10) --------------
    def _detect_service_account_rdp(self, events: list[EventLogEntry]) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[tuple[str, str]] = set()
        for e in events:
            if e.event_id != _SUCCESS_LOGON:
                continue
            if _logon_type(e) != _LOGON_TYPE_RDP:
                continue
            account = _target_account(e)
            if not _is_real_account(account):
                continue
            if not _looks_like_service_account(account):
                continue
            key = (account, e.computer)
            if key in seen:
                continue
            seen.add(key)
            findings.append(self._service_rdp_finding(account, e))
        return findings

    def _service_rdp_finding(self, account: str, entry: EventLogEntry) -> Finding:
        host = entry.computer or "unknown host"
        source = _source_label(entry) or "an unknown source"
        return Finding(
            title=f"Service account '{account}' used for RDP logon to {host}",
            description=(
                f"Service-style account '{account}' performed a remote-interactive "
                f"(RDP, LogonType 10) logon to {host} from {source}. Service "
                "accounts should authenticate non-interactively; an RDP session "
                "under one is credential abuse / valid-account misuse (MITRE T1078)."
            ),
            finding_type="behavior",
            severity="high",
            category=FindingCategory.LATERAL_MOVEMENT,
            evidence={
                "signal": "service_account_rdp",
                "account": account,
                "host": host,
                "source": source,
                "logon_type": _LOGON_TYPE_RDP,
                "mitre": "T1078",
            },
            confidence=0.78,
            confidence_label="High",
            reasoning_chain=[
                f"'{account}' reads like a service account.",
                f"It logged on to {host} via RDP (LogonType 10) from {source}.",
                "Interactive logon by a service account is valid-account abuse "
                "(MITRE T1078).",
            ],
            artifact_sources=["evtx"],
        )

    # --- Signal 3: cross-host account spread (4624/4648) ------------------
    def _detect_cross_host_spread(self, events: list[EventLogEntry]) -> list[Finding]:
        acct_hosts: dict[str, set[str]] = defaultdict(set)
        for e in events:
            if e.event_id not in (_SUCCESS_LOGON, _EXPLICIT_CRED):
                continue
            account = _target_account(e)
            if not _is_real_account(account):
                continue
            if e.computer:
                acct_hosts[account].add(e.computer)

        findings: list[Finding] = []
        for account, hosts in acct_hosts.items():
            if len(hosts) >= self.cross_host_threshold:
                findings.append(self._cross_host_finding(account, hosts))
        return findings

    def _cross_host_finding(self, account: str, hosts: set[str]) -> Finding:
        host_list = sorted(hosts)
        return Finding(
            title=f"Account '{account}' authenticated across {len(host_list)} hosts",
            description=(
                f"Account '{account}' authenticated to {len(host_list)} distinct "
                f"hosts ({', '.join(host_list)}), at or above the "
                f"{self.cross_host_threshold}-host threshold. A single account "
                "fanning out across many hosts is the operator's lateral pivot "
                "footprint (MITRE T1021)."
            ),
            finding_type="behavior",
            severity="high",
            category=FindingCategory.LATERAL_MOVEMENT,
            evidence={
                "signal": "cross_host_spread",
                "account": account,
                "hosts": host_list,
                "host_count": len(host_list),
                "threshold": self.cross_host_threshold,
                "mitre": "T1021",
            },
            confidence=0.82,
            confidence_label="High",
            reasoning_chain=[
                f"'{account}' authenticated to {len(host_list)} hosts: "
                f"{', '.join(host_list)}.",
                f"That meets the cross-host threshold of {self.cross_host_threshold}.",
                "Broad cross-host authentication is a lateral-movement footprint "
                "(MITRE T1021).",
            ],
            artifact_sources=["evtx"],
        )

    # --- Signal 4: explicit-credential burst (4648) -----------------------
    def _detect_explicit_cred_bursts(
        self, events: list[EventLogEntry]
    ) -> list[Finding]:
        pairs: Counter[tuple[str, str]] = Counter()
        for e in events:
            if e.event_id != _EXPLICIT_CRED:
                continue
            account = _target_account(e)
            if not _is_real_account(account):
                continue
            if e.computer:
                pairs[(e.computer, account)] += 1

        findings: list[Finding] = []
        for (host, account), count in pairs.items():
            if count >= self.explicit_cred_threshold:
                findings.append(self._explicit_cred_finding(host, account, count))
        return findings

    def _explicit_cred_finding(self, host: str, account: str, count: int) -> Finding:
        return Finding(
            title=(f"Explicit-credential burst: '{account}' x{count} on {host}"),
            description=(
                f"Account '{account}' was used for {count} explicit-credential "
                f"logons (4648) on {host}, at or above the "
                f"{self.explicit_cred_threshold}-event threshold. Repeated runas / "
                "explicit-credential use on one host is a pass-the-hash or "
                "credential-reuse lateral-movement pattern (MITRE T1078)."
            ),
            finding_type="behavior",
            severity="high",
            category=FindingCategory.LATERAL_MOVEMENT,
            evidence={
                "signal": "explicit_cred_burst",
                "account": account,
                "host": host,
                "explicit_cred_count": count,
                "threshold": self.explicit_cred_threshold,
                "mitre": "T1078",
            },
            confidence=0.80,
            confidence_label="High",
            reasoning_chain=[
                f"'{account}' drove {count} explicit-credential logons (4648) "
                f"on {host}.",
                f"That meets the burst threshold of {self.explicit_cred_threshold}.",
                "Repeated explicit-credential use is runas / pass-the-hash "
                "lateral movement (MITRE T1078).",
            ],
            artifact_sources=["evtx"],
        )
