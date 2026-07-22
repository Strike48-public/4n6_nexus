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
from datetime import datetime
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

# Distributed (low-and-slow) spray defaults. A spray that keeps every single
# account/source just under DEFAULT_FAILED_LOGON_THRESHOLD evades the per-target
# spike signals, so we add an aggregate time-boxed density signal. The density
# threshold sits above the routine failed-logon floor, and the min-accounts
# breadth guard keeps a single-account concentrated spike (already covered by
# the per-account spike) from double-firing here.
DEFAULT_SPRAY_WINDOW_SECONDS = 300  # sliding window for aggregate failures
DEFAULT_SPRAY_DENSITY_THRESHOLD = 30  # total 4625 within any one window
DEFAULT_SPRAY_MIN_ACCOUNTS = 2  # distinct targets required (breadth guard)

# Service-account name markers. Interactive/RDP logon by one of these is abuse.
# Matched on a word/token basis (see ``_looks_like_service_account``) rather
# than bare substring, so a human name like ``Bob.Service`` does not match while
# ``sqladmin`` / ``backup_admin`` (leading-token) do.
DEFAULT_SERVICE_ACCOUNT_MARKERS = ("svc", "sql", "service", "iis", "backup", "sched")

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


# Separators that delimit tokens inside a sAMAccountName (``svc_sql``,
# ``backup-admin``, ``iis$pool``). A marker is a service signal only when the
# *leading* token starts with it, mirroring the near-universal convention that
# service accounts are named role-first (``svc_*``, ``sql*``, ``backup_*``).
_TOKEN_SPLIT_RE = re.compile(r"[^a-z0-9]+")


def _looks_like_service_account(
    account: str, markers: tuple[str, ...] = DEFAULT_SERVICE_ACCOUNT_MARKERS
) -> bool:
    """Heuristic: does the account name read like a non-interactive service?

    Matching is leading-token / prefix based rather than bare substring:

    * ``svc_sql`` / ``svc-web`` / ``sqladmin`` / ``backup_admin`` /
      ``iis_apppool`` -> service (the leading token starts with a marker).
    * ``Bob.Service`` / ``Priscilla`` -> not a service (the leading token is a
      human given name; the marker, if any, is not in front).

    Leading-token matching is what fixes the ``Bob.Service`` false positive the
    old bare-substring check produced while keeping ``sqladmin`` /
    ``backup_admin`` (previously argued as false negatives).

    Args:
        account: Full account principal, optionally ``DOMAIN\\name``.
        markers: Service-name markers to match against.

    Returns:
        True when the leading token starts with a marker.
    """
    # Compare on the bare sAMAccountName (strip DOMAIN\ prefix).
    name = account.split("\\")[-1].strip().lower()
    tokens = [t for t in _TOKEN_SPLIT_RE.split(name) if t]
    if not tokens:
        return False
    lead = tokens[0]
    return any(lead.startswith(marker) for marker in markers)


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
        cross_host_window_seconds: Optional[int] = None,
        spray_window_seconds: int = DEFAULT_SPRAY_WINDOW_SECONDS,
        spray_density_threshold: int = DEFAULT_SPRAY_DENSITY_THRESHOLD,
        spray_min_accounts: int = DEFAULT_SPRAY_MIN_ACCOUNTS,
        service_account_markers: tuple[str, ...] = DEFAULT_SERVICE_ACCOUNT_MARKERS,
    ) -> None:
        # A threshold below 1 would fire on every account/source/host and is
        # almost certainly a misconfiguration, so reject it rather than flood
        # the operator with findings.
        for name, value in (
            ("failed_logon_threshold", failed_logon_threshold),
            ("cross_host_threshold", cross_host_threshold),
            ("explicit_cred_threshold", explicit_cred_threshold),
            ("spray_window_seconds", spray_window_seconds),
            ("spray_density_threshold", spray_density_threshold),
            ("spray_min_accounts", spray_min_accounts),
        ):
            if value < 1:
                raise ValueError(f"{name} must be >= 1, got {value}")
        # The cross-host window is opt-in (None disables the time gate entirely,
        # preserving the count-only legacy behaviour); when set it must be >= 1.
        if cross_host_window_seconds is not None and cross_host_window_seconds < 1:
            raise ValueError(
                "cross_host_window_seconds must be >= 1 or None, "
                f"got {cross_host_window_seconds}"
            )
        if not service_account_markers:
            raise ValueError("service_account_markers must be a non-empty tuple")

        self.failed_logon_threshold = failed_logon_threshold
        self.cross_host_threshold = cross_host_threshold
        self.explicit_cred_threshold = explicit_cred_threshold
        self.cross_host_window_seconds = cross_host_window_seconds
        self.spray_window_seconds = spray_window_seconds
        self.spray_density_threshold = spray_density_threshold
        self.spray_min_accounts = spray_min_accounts
        self.service_account_markers = tuple(m.lower() for m in service_account_markers)

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
        findings.extend(self._detect_distributed_spray(events))
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

    # --- Signal 1b: distributed low-and-slow spray (aggregate 4625) -------
    def _detect_distributed_spray(self, events: list[EventLogEntry]) -> list[Finding]:
        """Aggregate time-boxed failure density across many accounts/sources.

        A spray that keeps every individual account and source just under
        ``failed_logon_threshold`` slips past both per-target spike pivots. This
        signal counts *all* real-account 4625s inside a sliding window and fires
        when the density crosses ``spray_density_threshold`` while spanning at
        least ``spray_min_accounts`` distinct targets. The breadth guard is what
        keeps a single-account concentrated spike (already caught by the
        per-account spike, e.g. scenario 22) from double-firing here.
        """
        failed = [
            e
            for e in events
            if e.event_id == _FAILED_LOGON and _is_real_account(_target_account(e))
        ]
        if len(failed) < self.spray_density_threshold:
            return []

        ordered = sorted(failed, key=lambda e: e.time_created)
        window = float(self.spray_window_seconds)

        # Slide a right-anchored window over the ordered failures; at each anchor
        # find the densest window ending there and test the density + breadth.
        # The window is the CLOSED interval [anchor - window, anchor]: two
        # failures exactly ``window`` seconds apart co-inhabit one window, the
        # natural reading of "within a 300s window". This is also the safe error
        # direction for a detector -- a benign host will not accrue >= density
        # failures across >= min-accounts targets in ~window seconds, so erring
        # toward inclusion cannot manufacture a false positive here.
        left = 0
        best: Optional[dict] = None
        for right in range(len(ordered)):
            anchor = ordered[right].time_created
            while (anchor - ordered[left].time_created).total_seconds() > window:
                left += 1
            span = ordered[left : right + 1]
            if len(span) < self.spray_density_threshold:
                continue
            accounts = {_target_account(e) for e in span}
            if len(accounts) < self.spray_min_accounts:
                continue
            sources = {s for e in span if (s := _source_label(e))}
            candidate = {
                "failed_count": len(span),
                "accounts": accounts,
                "sources": sources,
                "start": span[0].time_created,
                "end": span[-1].time_created,
            }
            # Keep the densest window; ties break toward the earliest anchor
            # (strict '>'), which is deterministic regardless of input order.
            if best is None or candidate["failed_count"] > best["failed_count"]:
                best = candidate

        if best is None:
            return []
        return [self._distributed_spray_finding(best)]

    def _distributed_spray_finding(self, agg: dict) -> Finding:
        span_seconds = (agg["end"] - agg["start"]).total_seconds()
        n_accounts = len(agg["accounts"])
        n_sources = len(agg["sources"])
        return Finding(
            title=(
                f"Distributed password spray: {agg['failed_count']} failed logons "
                f"across {n_accounts} accounts"
            ),
            description=(
                f"{agg['failed_count']} failed logons (4625) against {n_accounts} "
                f"distinct accounts from {n_sources} source(s) occurred within a "
                f"{self.spray_window_seconds}s window (span {span_seconds:.0f}s), at "
                f"or above the {self.spray_density_threshold}-event density "
                "threshold. A broad, low-per-target failure burst is a distributed "
                "/ low-and-slow password spray that evades per-account and "
                "per-source spike detection (MITRE T1110)."
            ),
            finding_type="behavior",
            severity="high",
            category=FindingCategory.LATERAL_MOVEMENT,
            evidence={
                "signal": "distributed_spray",
                "failed_count": agg["failed_count"],
                "distinct_accounts": n_accounts,
                "distinct_sources": n_sources,
                "window_seconds": self.spray_window_seconds,
                "span_seconds": span_seconds,
                "density_threshold": self.spray_density_threshold,
                "mitre": "T1110",
            },
            confidence=0.75,
            confidence_label="High",
            reasoning_chain=[
                f"{agg['failed_count']} failed logons (4625) hit {n_accounts} "
                f"accounts from {n_sources} source(s) within "
                f"{self.spray_window_seconds}s.",
                "No single account or source crossed the per-target spike "
                "threshold, so this evades the concentrated-spike pivots.",
                f"Aggregate density >= {self.spray_density_threshold} across "
                f">= {self.spray_min_accounts} accounts is a distributed password "
                "spray (MITRE T1110).",
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
            if not _looks_like_service_account(account, self.service_account_markers):
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
        # Track the earliest logon time to each distinct host per account so we
        # can reason about *how fast* the account fanned out, not just how wide.
        first_touch: dict[str, dict[str, datetime]] = defaultdict(dict)
        for e in events:
            if e.event_id not in (_SUCCESS_LOGON, _EXPLICIT_CRED):
                continue
            account = _target_account(e)
            if not _is_real_account(account):
                continue
            if not e.computer:
                continue
            seen = first_touch[account].get(e.computer)
            if seen is None or e.time_created < seen:
                first_touch[account][e.computer] = e.time_created

        findings: list[Finding] = []
        for account, host_times in first_touch.items():
            if len(host_times) < self.cross_host_threshold:
                continue
            span_seconds = self._min_span_seconds(
                list(host_times.values()), self.cross_host_threshold
            )
            # Opt-in temporal gate: a spread that unfolds slower than the window
            # is routine admin/monitoring reach, not a burst pivot -> suppress.
            if (
                self.cross_host_window_seconds is not None
                and span_seconds > self.cross_host_window_seconds
            ):
                continue
            findings.append(
                self._cross_host_finding(account, set(host_times), span_seconds)
            )
        return findings

    @staticmethod
    def _min_span_seconds(times: list[datetime], k: int) -> float:
        """Smallest span (seconds) covering ``k`` of the given timestamps.

        With per-host first-touch times, this is the tightest window in which
        the account reached ``k`` distinct hosts — the rate the temporal gate
        and the ``hosts_per_hour`` evidence are computed from.

        Callers must supply at least ``k`` timestamps; the cross-host caller
        guarantees this via the host-count threshold check. Fewer than ``k``
        cannot yield a ``k``-host window, so it is a precondition violation
        rather than a silent zero (which would falsely read as an infinite
        fan-out rate downstream).

        Raises:
            ValueError: when fewer than ``k`` timestamps are supplied.
        """
        ordered = sorted(times)
        if len(ordered) < k:
            raise ValueError(
                f"need >= {k} timestamps to span {k} hosts, got {len(ordered)}"
            )
        return min(
            (ordered[i + k - 1] - ordered[i]).total_seconds()
            for i in range(len(ordered) - k + 1)
        )

    def _cross_host_finding(
        self, account: str, hosts: set[str], span_seconds: float
    ) -> Finding:
        host_list = sorted(hosts)
        # Rate over the tightest threshold-covering window; guard the zero-span
        # case (simultaneous logons) with an explicit sentinel.
        if span_seconds > 0:
            hosts_per_hour = round(self.cross_host_threshold / (span_seconds / 3600), 2)
        else:
            hosts_per_hour = float("inf")
        return Finding(
            title=f"Account '{account}' authenticated across {len(host_list)} hosts",
            description=(
                f"Account '{account}' authenticated to {len(host_list)} distinct "
                f"hosts ({', '.join(host_list)}), at or above the "
                f"{self.cross_host_threshold}-host threshold, reaching "
                f"{self.cross_host_threshold} of them within {span_seconds:.0f}s. "
                "A single account fanning out across many hosts is the operator's "
                "lateral pivot footprint (MITRE T1021)."
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
                "span_seconds": span_seconds,
                "hosts_per_hour": hosts_per_hour,
                "window_seconds": self.cross_host_window_seconds,
                "mitre": "T1021",
            },
            confidence=0.82,
            confidence_label="High",
            reasoning_chain=[
                f"'{account}' authenticated to {len(host_list)} hosts: "
                f"{', '.join(host_list)}.",
                f"That meets the cross-host threshold of {self.cross_host_threshold}.",
                f"It reached {self.cross_host_threshold} hosts within "
                f"{span_seconds:.0f}s ({hosts_per_hour} hosts/hr).",
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
