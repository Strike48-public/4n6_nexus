#!/usr/bin/env python3
"""Cross-host logon-graph analysis for the SRL-2015 APT corpus (SFE-e3g).

Single-host sweeps cannot see lateral movement. This correlates the Security
event logs already extracted from all 7 hosts into a cross-host authentication
graph and surfaces the attack-chain signals:

  - source-host -> target-host logon edges (who authenticated where, from where)
  - failed-logon (4625) spikes per account/source — password spraying / brute
    force / disabled-account probing
  - explicit-credential logons (4648) — runas / pass-the-hash lateral movement
  - account spread — which accounts authenticated across many hosts (the
    operator's pivot accounts)

Read-only over the parsed CSVs under analysis/sweep/<host>/csv/security.csv.
Writes a report to analysis/SFE-e3g_logon_graph.md. No evidence is modified.

Usage:
    PYTHONPATH=. python3 analysis/apt_logon_graph.py
"""

from __future__ import annotations

import csv
import re
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path

_SWEEP = Path("analysis/sweep")
_AUTH_EVENT_IDS = {"4624", "4625", "4648", "4672"}
_LOGON_TYPE_RE = re.compile(r"LogonType\s+(\d+)")
_TARGET_RE = re.compile(r"Target:\s*(.+)", re.IGNORECASE)
_IP_RE = re.compile(r"\(([\d.]+)\)")

# Interactive / remote-interactive / network / batch / service logon types.
# Type 3 = network (SMB/Kerberos), 10 = RemoteInteractive (RDP), 2 = console,
# 4 = batch, 5 = service. RDP and explicit-cred network logons are the
# lateral-movement-relevant ones.
_LOGON_TYPE_NAMES = {
    "2": "Interactive",
    "3": "Network",
    "4": "Batch",
    "5": "Service",
    "7": "Unlock",
    "8": "NetworkCleartext",
    "9": "NewCredentials",
    "10": "RemoteInteractive(RDP)",
    "11": "CachedInteractive",
}


@dataclass(frozen=True)
class AuthEvent:
    host: str  # the host whose log this came from (the logon TARGET host)
    event_id: str
    time: str
    target_account: str
    source_host: str
    source_ip: str
    logon_type: str


def _host_label(sweep_stem: str) -> str:
    """Human label for a sweep directory name."""
    return (
        sweep_stem.replace("base-", "")
        .replace("-cdrive", "")
        .replace("-c-drive", "")
        .upper()
    )


def _clean(value: str | None) -> str:
    if not value:
        return ""
    return value.strip().strip("-").strip()


def parse_auth_events(csv_path: Path, host: str) -> list[AuthEvent]:
    events: list[AuthEvent] = []
    with csv_path.open(encoding="utf-8", errors="replace") as fh:
        for row in csv.DictReader(fh):
            eid = row.get("EventId", "")
            if eid not in _AUTH_EVENT_IDS:
                continue
            payloads = " ".join(row.get(f"PayloadData{i}", "") or "" for i in range(1, 7))
            target_match = _TARGET_RE.search(row.get("PayloadData1", "") or "")
            target = _clean(target_match.group(1)) if target_match else _clean(
                row.get("UserName")
            )
            lt_match = _LOGON_TYPE_RE.search(payloads)
            logon_type = lt_match.group(1) if lt_match else ""
            remote = row.get("RemoteHost", "") or ""
            ip_match = _IP_RE.search(remote)
            source_ip = ip_match.group(1) if ip_match else ""
            source_host = _clean(remote.split("(")[0]) if remote else ""
            events.append(
                AuthEvent(
                    host=host,
                    event_id=eid,
                    time=row.get("TimeCreated", ""),
                    target_account=target,
                    source_host=source_host,
                    source_ip=source_ip,
                    logon_type=logon_type,
                )
            )
    return events


def _is_machine_account(account: str) -> bool:
    """Machine accounts end in $ — routine domain chatter, not operator pivots."""
    return account.rstrip().endswith("$")


# Well-known local / virtual session principals that appear on every Windows
# host as a matter of course (compositor, font host, service SIDs). They are
# not domain accounts and never represent a cross-host pivot, so they only add
# noise to the account-spread graph.
_LOCAL_SESSION_PREFIXES = (
    "window manager\\",
    "font driver host\\",
    "nt authority\\",
    "nt service\\",
    "iis apppool\\",
    "dwm-",
    "umfd-",
)


def _is_noise_principal(account: str) -> bool:
    lowered = account.strip().lower()
    if not lowered or lowered in ("\\", ""):
        return True
    return any(lowered.startswith(p) for p in _LOCAL_SESSION_PREFIXES)


def build_report(all_events: dict[str, list[AuthEvent]]) -> str:
    flat = [e for events in all_events.values() for e in events]
    lines: list[str] = []
    lines.append("# SFE-e3g: SRL-2015 Cross-Host Logon Graph\n")
    lines.append(
        "Authentication correlation across 7 enterprise hosts. Source: Security "
        "event logs (4624 success, 4625 failed, 4648 explicit-cred, 4672 admin) "
        "extracted via pyewf+pytsk3, parsed with EvtxECmd. Read-only.\n"
    )

    # --- per-host event tallies ---
    lines.append("## Authentication events per host\n")
    lines.append("| Host | 4624 success | 4625 failed | 4648 explicit-cred | 4672 admin |")
    lines.append("|------|-------------|-------------|--------------------|------------|")
    for host in sorted(all_events):
        ids = Counter(e.event_id for e in all_events[host])
        lines.append(
            f"| {host} | {ids['4624']} | {ids['4625']} | {ids['4648']} | {ids['4672']} |"
        )
    lines.append("")

    # --- failed-logon hot spots (4625) ---
    lines.append("## Failed-logon hot spots (4625) — brute force / spraying / probing\n")
    failed = [e for e in flat if e.event_id == "4625"]
    by_target = Counter(e.target_account for e in failed if e.target_account)
    by_source = Counter(
        f"{e.source_host or '?'} ({e.source_ip or '?'})"
        for e in failed
        if e.source_host or e.source_ip
    )
    lines.append(f"Total failed logons across corpus: **{len(failed)}**\n")
    lines.append("Top failed-logon target accounts:")
    for acct, n in by_target.most_common(12):
        flag = "  [machine acct]" if _is_machine_account(acct) else ""
        lines.append(f"- `{acct}` x{n}{flag}")
    lines.append("\nTop failed-logon source hosts:")
    for src, n in by_source.most_common(12):
        lines.append(f"- {src} x{n}")
    lines.append("")

    # --- explicit-credential logons (4648) — lateral movement ---
    lines.append("## Explicit-credential logons (4648) — runas / lateral movement\n")
    explicit = [e for e in flat if e.event_id == "4648"]
    explicit_user = [
        e
        for e in explicit
        if not _is_machine_account(e.target_account)
        and not _is_noise_principal(e.target_account)
    ]
    lines.append(
        f"Total 4648 across corpus: **{len(explicit)}** "
        f"({len(explicit_user)} to user accounts, the rest machine accounts).\n"
    )
    pairs = Counter(
        (e.host, e.target_account)
        for e in explicit_user
        if e.target_account
    )
    lines.append("User-account explicit-credential use (target-host, account):")
    for (host, acct), n in pairs.most_common(20):
        lines.append(f"- {host}: `{acct}` x{n}")
    lines.append("")

    # --- cross-host account spread (pivot accounts) ---
    lines.append("## Cross-host account spread — pivot-account candidates\n")
    acct_hosts: dict[str, set[str]] = defaultdict(set)
    for e in flat:
        if (
            e.event_id in ("4624", "4648")
            and e.target_account
            and not _is_machine_account(e.target_account)
            and not _is_noise_principal(e.target_account)
        ):
            acct_hosts[e.target_account].add(e.host)
    spread = sorted(acct_hosts.items(), key=lambda kv: len(kv[1]), reverse=True)
    lines.append("Accounts that authenticated to multiple hosts (lateral footprint):")
    for acct, hosts in spread:
        if len(hosts) < 2:
            continue
        lines.append(f"- `{acct}` -> {len(hosts)} hosts: {', '.join(sorted(hosts))}")
    lines.append("")

    # --- RDP / remote-interactive edges (10) ---
    lines.append("## Remote-interactive (RDP, LogonType 10) edges\n")
    rdp = [
        e
        for e in flat
        if e.event_id == "4624"
        and e.logon_type == "10"
        and not _is_machine_account(e.target_account)
    ]
    rdp_edges = Counter(
        (e.source_host or e.source_ip or "?", e.host, e.target_account) for e in rdp
    )
    lines.append(f"Total user RDP logons: **{len(rdp)}**\n")
    lines.append("Source -> target-host as account (RDP):")
    for (src, tgt, acct), n in rdp_edges.most_common(25):
        lines.append(f"- {src} -> {tgt} as `{acct}` x{n}")
    lines.append("")

    return "\n".join(lines)


def main() -> int:
    all_events: dict[str, list[AuthEvent]] = {}
    for host_dir in sorted(_SWEEP.iterdir()):
        csv_path = host_dir / "csv" / "security.csv"
        if not csv_path.is_file():
            continue
        host = _host_label(host_dir.name)
        events = parse_auth_events(csv_path, host)
        all_events[host] = events
        print(f"{host:14} {len(events)} auth events")
    if not all_events:
        print("no security.csv files found under analysis/sweep/", file=sys.stderr)
        return 1
    report = build_report(all_events)
    out = Path("analysis/SFE-e3g_logon_graph.md")
    out.write_text(report, encoding="utf-8")
    print(f"\nreport -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
