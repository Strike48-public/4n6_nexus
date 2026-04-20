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
from ..parsers.pcap_parser import DNSQuery, HTTPRequest, SMTPMessage
from ..self_correction.engine import Finding
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
    ):
        self.webmail_exfil = webmail_exfil or WebmailExfilDetector()

    def analyze(
        self,
        browser_history: Optional[Iterable[BrowserHistoryEntry]] = None,
        mft_records: Optional[Iterable[MFTAccessRecord]] = None,
        http_requests: Optional[Iterable[HTTPRequest]] = None,
        dns_queries: Optional[Iterable[DNSQuery]] = None,
        smtp_messages: Optional[Iterable[SMTPMessage]] = None,
    ) -> list[Finding]:
        """Run every applicable sub-detector and return merged findings.

        Parameters that are `None` are treated as "this artifact stream was
        not collected" — the corresponding sub-detectors simply do not fire.
        An empty iterable is different: it means the artifact was collected
        but contained zero records, which is still meaningful (e.g. empty
        browser history can confirm an account was not used).
        """
        findings: list[Finding] = []

        if browser_history is not None:
            findings.extend(
                self.webmail_exfil.analyze(
                    browser_history=browser_history,
                    mft_records=mft_records,
                    http_requests=http_requests,
                )
            )

        # Placeholder for future sub-detectors that consume DNS / SMTP /
        # raw HTTP without browser history context. Kept explicit so the
        # signature advertises the orchestrator's full input surface.
        _ = dns_queries, smtp_messages

        return findings
