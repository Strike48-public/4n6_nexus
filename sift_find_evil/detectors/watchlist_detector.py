"""Watchlist-match detectors: suspicious hosts, offensive packages, cleartext ports.

A single detector family, because the shape is the same: iterate parsed events,
match a field against a YAML-backed table, emit one finding per distinct match.

Three tenants today:

- ``SuspiciousHostDetector``: matches DNS query names and HTTP Host headers
  against categories (paste drops, hacking tutorials, offensive package mirrors,
  anonymous file hosts). Addresses SFE-m82.

- ``OffensivePackageInstallDetector``: matches HTTP GETs against known
  offensive-tool .deb/.rpm filenames and mirrors. Addresses SFE-cpg.

- ``CleartextProtocolDetector``: matches TCP conversation ports against a
  cleartext-sensitive-port list (IMAP/POP/SMTP/NFS/rsyslog/FTP/Telnet/HTTP-with-auth).
  Addresses SFE-dar.

Each tenant emits findings with ``FindingCategory.UNKNOWN`` today — the taxonomy
in ``findings.categories`` has no slot for "policy violation" or "attacker prep"
yet. A follow-up should either add those categories or route these into
``PERSISTENCE`` (offensive tool installed) and ``ANTI_FORENSICS`` (cleartext
exposure hinders post-hoc analysis). Until then, ``UNKNOWN`` is the documented
escape hatch.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable, Optional

from ..findings import FindingCategory
from ..parsers.pcap_parser import DNSQuery, HTTPRequest, TCPConversation
from ..findings import Finding


# --- default watchlists ------------------------------------------------------

_DEFAULT_HOST_CATEGORIES: dict[str, tuple[str, ...]] = {
    "paste_drops": (
        "pastebin.com",
        "pastebin.pl",
        "pastebin.bl",
        "ghostbin.com",
        "hastebin.com",
        "ix.io",
        "privatebin.net",
        "dpaste.org",
        "paste.ee",
        "0x0.st",
    ),
    "hacking_tutorials": (
        "null-byte.wonderhowto.com",
        "wonderhowto.com",
        "offensive-security.com",
        "hackthebox.com",
        "hackthebox.eu",
        "tryhackme.com",
        "exploit-db.com",
    ),
    "offensive_package_mirrors": (
        "downloads.metasploit.com",
        "archive.kali.org",
        "http.kali.org",
        "john.openwall.com",
    ),
    # Anonymous / abuse-favored file hosts only. Mainstream consumer services
    # (wetransfer, mega, mediafire, 4shared, sendspace) were removed: they see
    # heavy legitimate business/personal use, so flagging their hostname alone as
    # a "suspicious host" is a false positive (the SFE-9nm class -- necessary, not
    # sufficient). Genuine exfiltration to those services is still caught by the
    # cloud-upload detector, which requires correlated upload + sensitive-file
    # signals rather than mere hostname presence.
    "anon_file_hosts": (
        "anonfiles.com",
        "transfer.sh",
        "file.io",
    ),
}

_DEFAULT_OFFENSIVE_PACKAGES: tuple[str, ...] = (
    "metasploit-framework",
    "john",
    "hydra",
    "hashcat",
    "sqlmap",
    "aircrack-ng",
    "responder",
    "impacket",
    "bloodhound",
    "powersploit",
    "nikto",
    "dirb",
    "gobuster",
    "ettercap",
    "burpsuite",
    "mimikatz",
    "crackmapexec",
    "bettercap",
    "wifite",
)

_DEFAULT_CLEARTEXT_PORTS: dict[int, str] = {
    21: "FTP",
    23: "Telnet",
    25: "SMTP (pre-STARTTLS)",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    161: "SNMP",
    389: "LDAP (unencrypted)",
    514: "Syslog/rsyslog-over-TCP",
    2049: "NFS",
}

# Ports where cleartext is expected (web traffic) — do not flag 80 bare.
_CLEARTEXT_PORTS_REQUIRING_CONTEXT: frozenset[int] = frozenset({80})


@dataclass(frozen=True)
class HostMatch:
    """Internal record of a host watchlist hit."""

    category: str
    matched_host: str
    src_ip: str
    count: int
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None


# --- suspicious hosts --------------------------------------------------------


class SuspiciousHostDetector:
    """Flag DNS queries and HTTP hosts that match a category watchlist."""

    def __init__(
        self,
        host_categories: Optional[dict[str, tuple[str, ...]]] = None,
    ):
        self.host_categories = host_categories or _DEFAULT_HOST_CATEGORIES
        self._compiled = {
            cat: tuple(h.lower() for h in hosts)
            for cat, hosts in self.host_categories.items()
        }

    def analyze(
        self,
        dns_queries: Optional[Iterable[DNSQuery]] = None,
        http_requests: Optional[Iterable[HTTPRequest]] = None,
    ) -> list[Finding]:
        """Return one finding per (src_ip, host) hit, grouped across artifacts."""
        hits: dict[tuple[str, str, str], list[str]] = {}

        for q in dns_queries or ():
            cat = self._categorize(q.query_name)
            if cat is None:
                continue
            key = (cat, q.src_ip, self._normalize_host(q.query_name))
            hits.setdefault(key, []).append(q.timestamp.isoformat())

        for r in http_requests or ():
            cat = self._categorize(r.host)
            if cat is None:
                continue
            key = (cat, r.src_ip, self._normalize_host(r.host))
            hits.setdefault(key, []).append(r.timestamp.isoformat())

        return [self._build_finding(k, ts) for k, ts in sorted(hits.items())]

    def _categorize(self, host: str) -> Optional[str]:
        if not host:
            return None
        lowered = self._normalize_host(host)
        # Skip DNS-SD / mDNS service-discovery names (e.g. _http._tcp.foo).
        if lowered.startswith("_") or ".local" in lowered.split("."):
            return None
        for cat, entries in self._compiled.items():
            for entry in entries:
                if lowered == entry or lowered.endswith("." + entry):
                    return cat
        return None

    @staticmethod
    def _normalize_host(host: str) -> str:
        """Strip protocol, trailing port, and trailing dot; lowercase."""
        lowered = host.lower().strip()
        if "://" in lowered:
            lowered = lowered.split("://", 1)[1]
        lowered = lowered.split("/", 1)[0]
        if ":" in lowered:
            lowered = lowered.split(":", 1)[0]
        return lowered.rstrip(".")

    def _build_finding(
        self, key: tuple[str, str, str], timestamps: list[str]
    ) -> Finding:
        category, src_ip, host = key
        timestamps_sorted = sorted(timestamps)
        first, last = timestamps_sorted[0], timestamps_sorted[-1]
        count = len(timestamps_sorted)
        severity = "high" if category in ("offensive_package_mirrors",) else "medium"

        return Finding(
            title=f"Suspicious host access: {host} ({category})",
            description=(
                f"Host {src_ip} accessed {host} {count} time(s) between "
                f"{first} and {last}. Category: {category}."
            ),
            finding_type="indicator",
            severity=severity,
            category=FindingCategory.UNKNOWN,
            evidence={
                "host": host,
                "watchlist_category": category,
                "src_ip": src_ip,
                "access_count": count,
                "first_seen": first,
                "last_seen": last,
            },
            confidence=0.70,
            confidence_label="Medium",
            reasoning_chain=[
                f"{host} appears in the '{category}' watchlist.",
                f"{src_ip} accessed it {count} time(s) in the capture window.",
            ],
            artifact_sources=["pcap"],
        )


# --- offensive-package installs ---------------------------------------------

_DEB_URI_RE = re.compile(
    r"/([A-Za-z0-9][A-Za-z0-9._+-]*)_(\d[^_/]*)_[A-Za-z0-9_]+\.deb"
)


class OffensivePackageInstallDetector:
    """Flag HTTP GETs of .deb (or similar) packages matching an offensive-tool list."""

    def __init__(
        self,
        package_names: Optional[Iterable[str]] = None,
        offensive_mirrors: Optional[Iterable[str]] = None,
    ):
        self.package_names = frozenset((package_names or _DEFAULT_OFFENSIVE_PACKAGES))
        self.offensive_mirrors = frozenset(
            offensive_mirrors or _DEFAULT_HOST_CATEGORIES["offensive_package_mirrors"]
        )

    def analyze(
        self,
        http_requests: Optional[Iterable[HTTPRequest]] = None,
    ) -> list[Finding]:
        """Return one finding per (src_ip, package) hit."""
        hits: dict[tuple[str, str], dict] = {}
        for r in http_requests or ():
            if r.method != "GET":
                continue
            pkg = self._match_package(r.uri)
            mirror_hit = self._match_mirror(r.host)
            if pkg is None and not mirror_hit:
                continue
            key = (r.src_ip, pkg or r.host.lower())
            entry = hits.setdefault(
                key,
                {
                    "timestamps": [],
                    "uris": [],
                    "hosts": set(),
                    "matched_mirror": False,
                    "package": pkg,
                },
            )
            entry["timestamps"].append(r.timestamp.isoformat())
            entry["uris"].append(r.uri)
            entry["hosts"].add(r.host.lower())
            if mirror_hit:
                entry["matched_mirror"] = True
        return [self._build_finding(k, v) for k, v in sorted(hits.items())]

    def _match_package(self, uri: str) -> Optional[str]:
        for pkg in self.package_names:
            # Decoded form or URL-encoded (%2b for +).
            if f"/{pkg}_" in uri.lower() or f"/{pkg}-data_" in uri.lower():
                return pkg
        m = _DEB_URI_RE.search(uri)
        if m and m.group(1).lower() in self.package_names:
            return m.group(1).lower()
        return None

    def _match_mirror(self, host: str) -> bool:
        lowered = host.lower()
        if ":" in lowered:
            lowered = lowered.split(":", 1)[0]
        return any(
            lowered == m or lowered.endswith("." + m) for m in self.offensive_mirrors
        )

    def _build_finding(self, key: tuple[str, str], entry: dict) -> Finding:
        src_ip, pkg_or_host = key
        timestamps = sorted(entry["timestamps"])
        hosts = sorted(entry["hosts"])
        pkg = entry["package"]
        title_subject = (
            f"offensive package {pkg}"
            if pkg
            else f"offensive-tool mirror {pkg_or_host}"
        )
        return Finding(
            title=f"Offensive tool install from {src_ip}: {title_subject}",
            description=(
                f"Host {src_ip} downloaded {title_subject} from "
                f"{', '.join(hosts)} at {timestamps[0]}."
                + (
                    " Download source is a known offensive-tool mirror."
                    if entry["matched_mirror"]
                    else ""
                )
            ),
            finding_type="behavior",
            severity="high",
            category=FindingCategory.UNKNOWN,
            evidence={
                "src_ip": src_ip,
                "package": pkg,
                "hosts": hosts,
                "uris": entry["uris"],
                "first_seen": timestamps[0],
                "last_seen": timestamps[-1],
                "matched_mirror": entry["matched_mirror"],
            },
            confidence=0.80 if pkg else 0.65,
            confidence_label="High" if pkg else "Medium",
            reasoning_chain=[
                f"{src_ip} issued an HTTP GET for a known offensive package.",
                f"Package(s): {pkg or '(mirror-only match)'}",
                f"Host(s): {', '.join(hosts)}",
            ],
            artifact_sources=["pcap"],
        )


# --- cleartext sensitive protocols ------------------------------------------


class CleartextProtocolDetector:
    """Flag TCP conversations on sensitive ports that should be encrypted."""

    def __init__(
        self,
        cleartext_ports: Optional[dict[int, str]] = None,
        min_frames: int = 5,
    ):
        self.cleartext_ports = cleartext_ports or _DEFAULT_CLEARTEXT_PORTS
        self.min_frames = min_frames

    def analyze(
        self,
        tcp_conversations: Optional[Iterable[TCPConversation]] = None,
    ) -> list[Finding]:
        """Return one finding per (port, label) aggregated across conversations."""
        by_port: dict[int, dict] = {}
        for conv in tcp_conversations or ():
            port = conv.service_port()
            if port is None or port not in self.cleartext_ports:
                continue
            if port in _CLEARTEXT_PORTS_REQUIRING_CONTEXT:
                continue
            if conv.total_frames < self.min_frames:
                continue
            entry = by_port.setdefault(
                port,
                {
                    "label": self.cleartext_ports[port],
                    "total_frames": 0,
                    "total_bytes": 0,
                    "pairs": set(),
                },
            )
            entry["total_frames"] += conv.total_frames
            entry["total_bytes"] += conv.total_bytes
            entry["pairs"].add((conv.endpoint_a_ip, conv.endpoint_b_ip))
        return [self._build_finding(p, e) for p, e in sorted(by_port.items())]

    def _build_finding(self, port: int, entry: dict) -> Finding:
        pairs = sorted(entry["pairs"])
        return Finding(
            title=f"Cleartext {entry['label']} traffic on port {port}",
            description=(
                f"{entry['total_frames']} frame(s) of cleartext {entry['label']} "
                f"traffic observed across {len(pairs)} host pair(s). "
                f"Sensitive data (credentials, mail, syslog) may be exposed on the wire."
            ),
            finding_type="indicator",
            severity="medium",
            category=FindingCategory.UNKNOWN,
            evidence={
                "port": port,
                "protocol_label": entry["label"],
                "total_frames": entry["total_frames"],
                "total_bytes": entry["total_bytes"],
                "host_pairs": [{"src": a, "dst": b} for a, b in pairs[:10]],
                "host_pair_count": len(pairs),
            },
            confidence=0.75,
            confidence_label="High",
            reasoning_chain=[
                f"Port {port} ({entry['label']}) carries sensitive data in cleartext.",
                f"Observed {entry['total_frames']} frame(s) across "
                f"{len(pairs)} host pair(s).",
            ],
            artifact_sources=["pcap"],
        )
