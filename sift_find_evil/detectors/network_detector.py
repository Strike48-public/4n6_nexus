"""Network-layer detector orchestrator.

Owns the network-forensics detection surface. Individual sub-detectors
(webmail exfil, beaconing, DNS tunneling, suspicious TLD, large upload) live
alongside this file and are invoked by `analyze(...)`. Callers get one unified
list of `Finding` objects regardless of how many sub-detectors contributed.

For the 2026-04-19 detector slice only `WebmailExfilDetector` is integrated
via the `analyze_with_browser_history` path. Pure-PCAP sub-detectors (C2
beaconing, DNS tunneling) are follow-up work; this orchestrator is shaped so
they plug in without re-threading the CLI.
"""

from __future__ import annotations

from typing import Iterable, Optional

from ..parsers.browser_history_parser import BrowserHistoryEntry
from ..parsers.pcap_parser import DNSQuery, HTTPRequest, SMTPMessage, TCPConversation
from ..findings import Finding
from .cloud_upload_detector import CloudUploadDetector
from .exfil_ratio_detector import ExfilRatioDetector
from .stats_detector import BeaconingDetector, DNSAnomalyDetector
from .watchlist_detector import (
    CleartextProtocolDetector,
    OffensivePackageInstallDetector,
    SuspiciousHostDetector,
)
from .webmail_exfil_detector import MFTAccessRecord, WebmailExfilDetector


class NetworkDetector:
    """Run network-layer detectors and return unified findings.

    The detector is stateless — `analyze` can be called multiple times with
    different artifact sets. Sub-detectors are instantiated lazily so that
    callers who only need one artifact stream don't pay for unused ones.
    """

    def __init__(
        self,
        webmail_exfil: Optional[WebmailExfilDetector] = None,
        cloud_upload: Optional[CloudUploadDetector] = None,
        suspicious_host: Optional[SuspiciousHostDetector] = None,
        offensive_package: Optional[OffensivePackageInstallDetector] = None,
        cleartext_protocol: Optional[CleartextProtocolDetector] = None,
        beaconing: Optional[BeaconingDetector] = None,
        dns_anomaly: Optional[DNSAnomalyDetector] = None,
        exfil_ratio: Optional[ExfilRatioDetector] = None,
    ):
        self.webmail_exfil = webmail_exfil or WebmailExfilDetector()
        self.cloud_upload = cloud_upload or CloudUploadDetector()
        self.suspicious_host = suspicious_host or SuspiciousHostDetector()
        self.offensive_package = offensive_package or OffensivePackageInstallDetector()
        self.cleartext_protocol = cleartext_protocol or CleartextProtocolDetector()
        self.beaconing = beaconing or BeaconingDetector()
        self.dns_anomaly = dns_anomaly or DNSAnomalyDetector()
        self.exfil_ratio = exfil_ratio or ExfilRatioDetector()

    def analyze(
        self,
        browser_history: Optional[Iterable[BrowserHistoryEntry]] = None,
        mft_records: Optional[Iterable[MFTAccessRecord]] = None,
        http_requests: Optional[Iterable[HTTPRequest]] = None,
        dns_queries: Optional[Iterable[DNSQuery]] = None,
        smtp_messages: Optional[Iterable[SMTPMessage]] = None,
        tcp_conversations: Optional[Iterable[TCPConversation]] = None,
    ) -> list[Finding]:
        """Run every applicable sub-detector and return merged findings.

        Parameters that are `None` are treated as "this artifact stream was
        not collected" — the corresponding sub-detectors simply do not fire.
        An empty iterable is different: it means the artifact was collected
        but contained zero records, which is still meaningful (e.g. empty
        browser history can confirm an account was not used).
        """
        findings: list[Finding] = []

        http_list = list(http_requests) if http_requests is not None else None
        dns_list = list(dns_queries) if dns_queries is not None else None
        mft_list = list(mft_records) if mft_records is not None else None

        if browser_history is not None:
            history_list = list(browser_history)
            findings.extend(
                self.webmail_exfil.analyze(
                    browser_history=history_list,
                    mft_records=mft_list,
                    http_requests=http_list,
                )
            )
            findings.extend(
                self.cloud_upload.analyze(
                    browser_history=history_list,
                    mft_records=mft_list,
                    http_requests=http_list,
                )
            )

        if dns_list is not None or http_list is not None:
            findings.extend(
                self.suspicious_host.analyze(
                    dns_queries=dns_list,
                    http_requests=http_list,
                )
            )

        if http_list is not None:
            findings.extend(self.offensive_package.analyze(http_requests=http_list))
            findings.extend(self.beaconing.analyze(http_requests=http_list))

        if dns_list is not None:
            findings.extend(self.dns_anomaly.analyze(dns_queries=dns_list))

        if tcp_conversations is not None:
            conv_list = list(tcp_conversations)
            findings.extend(
                self.cleartext_protocol.analyze(tcp_conversations=conv_list)
            )
            findings.extend(
                self.exfil_ratio.analyze(
                    tcp_conversations=conv_list,
                    dns_queries=dns_list,
                )
            )

        _ = smtp_messages  # reserved for future SMTP-based sub-detectors

        return findings
