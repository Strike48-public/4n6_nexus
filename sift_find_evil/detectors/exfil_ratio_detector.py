"""Asymmetric-byte-ratio exfiltration detector.

Flags TCP conversations whose outbound bytes vastly exceed inbound bytes — the
classic ``client uploaded a lot more than it downloaded`` shape of data
exfiltration via HTTPS POST, SFTP, SCP, etc.

Shape: consumes ``TCPConversation`` records and (optionally) the DNS query
stream. A conversation is flagged when:

1. One endpoint's ``bytes_*_to_*`` dwarfs the other by at least ``min_ratio``
   (default 5x), AND
2. The heavier-direction byte count exceeds ``min_outbound_bytes`` (default
   500 kB — below this, a single image upload or TLS handshake dominates the
   ratio and produces false positives), AND
3. The server-side port is a "carry a lot of data" port — HTTPS (443), HTTP
   (80), FTP-data (20), SSH/SFTP (22), SMB (445), or anything configured.

As a *bonus* sub-signal, the detector marks the finding as higher-confidence
when the destination IP has **no preceding DNS query** in the supplied
``dns_queries`` list — IP-literal TLS to an unresolved IP is unusual for
benign browser traffic and characteristic of custom tooling.

Addresses SFE-84s.
"""

from __future__ import annotations

from typing import Iterable, Optional

from ..findings import FindingCategory
from ..parsers.pcap_parser import DNSQuery, TCPConversation
from ..self_correction.engine import Finding


_DEFAULT_DATA_PORTS: frozenset[int] = frozenset(
    {20, 21, 22, 80, 443, 445, 993, 995, 8080, 8443}
)


class ExfilRatioDetector:
    """Flag TCP flows where outbound bytes >> inbound bytes.

    Parameters
    ----------
    min_ratio:
        Minimum outbound/inbound byte ratio for a conversation to be flagged.
        Default 5.0 - below this, routine HTTPS POSTs of form data dominate.
    min_outbound_bytes:
        Minimum absolute outbound bytes. Small uploads (e.g. a handful of
        POST parameters) trip any ratio threshold, so require a floor. Default
        500 kB.
    data_ports:
        Server-side ports considered data-bearing. Conversations on other
        ports (DNS UDP, NTP, etc.) are skipped. Default includes common
        web/SSH/SMB/mail ports.
    """

    def __init__(
        self,
        min_ratio: float = 5.0,
        min_outbound_bytes: int = 500_000,
        data_ports: Optional[Iterable[int]] = None,
    ):
        if min_ratio <= 1.0:
            raise ValueError("min_ratio must be > 1.0")
        if min_outbound_bytes <= 0:
            raise ValueError("min_outbound_bytes must be positive")
        self.min_ratio = min_ratio
        self.min_outbound_bytes = min_outbound_bytes
        self.data_ports = frozenset(data_ports) if data_ports else _DEFAULT_DATA_PORTS

    def analyze(
        self,
        tcp_conversations: Optional[Iterable[TCPConversation]] = None,
        dns_queries: Optional[Iterable[DNSQuery]] = None,
    ) -> list[Finding]:
        """Return one finding per outbound-heavy conversation on a data port."""
        if not tcp_conversations:
            return []

        resolved_ips = self._resolved_ips(dns_queries)

        findings: list[Finding] = []
        for conv in tcp_conversations:
            port = conv.service_port()
            if port is None or port not in self.data_ports:
                continue
            client_ip, server_ip, out_bytes, in_bytes = self._split_client_server(
                conv, port
            )
            if out_bytes < self.min_outbound_bytes:
                continue
            ratio = out_bytes / max(in_bytes, 1)
            if ratio < self.min_ratio:
                continue
            is_ip_literal = resolved_ips is not None and server_ip not in resolved_ips
            findings.append(
                self._build_finding(
                    conv=conv,
                    client_ip=client_ip,
                    server_ip=server_ip,
                    server_port=port,
                    out_bytes=out_bytes,
                    in_bytes=in_bytes,
                    ratio=ratio,
                    is_ip_literal=is_ip_literal,
                )
            )
        return findings

    @staticmethod
    def _resolved_ips(
        dns_queries: Optional[Iterable[DNSQuery]],
    ) -> Optional[set[str]]:
        """Return the set of IPs that appeared as DNS responses in the capture.

        Returns ``None`` when no DNS stream was supplied — the caller cannot
        reason about "IP-literal" in that case, and the detector suppresses
        that sub-signal rather than emitting a false positive.
        """
        if dns_queries is None:
            return None
        resolved: set[str] = set()
        for q in dns_queries:
            if q.response_ip:
                resolved.add(q.response_ip)
        return resolved

    @staticmethod
    def _split_client_server(
        conv: TCPConversation, server_port: int
    ) -> tuple[str, str, int, int]:
        """Identify which endpoint is the server, and return outbound/inbound bytes."""
        if conv.endpoint_b_port == server_port:
            client_ip = conv.endpoint_a_ip
            server_ip = conv.endpoint_b_ip
            out_bytes = conv.bytes_a_to_b
            in_bytes = conv.bytes_b_to_a
        else:
            client_ip = conv.endpoint_b_ip
            server_ip = conv.endpoint_a_ip
            out_bytes = conv.bytes_b_to_a
            in_bytes = conv.bytes_a_to_b
        return client_ip, server_ip, out_bytes, in_bytes

    def _build_finding(
        self,
        conv: TCPConversation,
        client_ip: str,
        server_ip: str,
        server_port: int,
        out_bytes: int,
        in_bytes: int,
        ratio: float,
        is_ip_literal: bool,
    ) -> Finding:
        # Confidence: base on magnitude of ratio (capped), bonus for IP-literal.
        base = min(0.85, 0.55 + (ratio - self.min_ratio) * 0.02)
        if is_ip_literal:
            base = min(0.95, base + 0.10)
        return Finding(
            title=(
                f"Asymmetric outbound transfer: {client_ip} -> "
                f"{server_ip}:{server_port}"
            ),
            description=(
                f"{client_ip} sent {self._fmt_bytes(out_bytes)} to "
                f"{server_ip}:{server_port} but received only "
                f"{self._fmt_bytes(in_bytes)} back (ratio {ratio:.1f}x)."
                + (
                    " Destination IP had no preceding DNS query — IP-literal "
                    "connection is unusual for benign web traffic."
                    if is_ip_literal
                    else ""
                )
            ),
            finding_type="behavior",
            severity="high",
            category=FindingCategory.DATA_EXFILTRATION,
            evidence={
                "client_ip": client_ip,
                "server_ip": server_ip,
                "server_port": server_port,
                "outbound_bytes": out_bytes,
                "inbound_bytes": in_bytes,
                "outbound_inbound_ratio": round(ratio, 2),
                "total_frames": conv.total_frames,
                "ip_literal_connection": is_ip_literal,
            },
            confidence=round(base, 2),
            confidence_label="High" if base >= 0.75 else "Medium",
            reasoning_chain=[
                f"{client_ip} -> {server_ip}:{server_port} is outbound-heavy: "
                f"{self._fmt_bytes(out_bytes)} out vs {self._fmt_bytes(in_bytes)} in.",
                f"Outbound/inbound ratio {ratio:.1f}x exceeds threshold "
                f"{self.min_ratio:.1f}x.",
                (
                    "No DNS query resolved to this destination IP — IP-literal TLS "
                    "is characteristic of custom or off-the-shelf C2 tooling."
                    if is_ip_literal
                    else "Server IP was previously resolved via DNS."
                ),
            ],
            artifact_sources=["pcap"],
        )

    @staticmethod
    def _fmt_bytes(n: int) -> str:
        for unit in ("B", "kB", "MB", "GB"):
            if n < 1024:
                return f"{n:.1f} {unit}"
            n = n / 1024  # type: ignore[assignment]
        return f"{n:.1f} TB"
