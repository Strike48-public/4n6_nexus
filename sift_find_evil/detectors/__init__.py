"""Detectors emit case-agnostic Findings from parsed artifacts.

A detector takes one or more parsed artifact streams (browser history, PCAP
records, MFT entries, Volatility plugin output, etc.) and returns a list of
`Finding` objects tagged with the appropriate `FindingCategory`. Detectors must
not modify their inputs and must not perform I/O beyond what their public
interface declares.
"""

from __future__ import annotations

from .exfil_ratio_detector import ExfilRatioDetector
from .lnk_jumplist_detector import LnkJumpListDetector
from .network_detector import NetworkDetector
from .registry_detector import RegistryDetector
from .stats_detector import BeaconingDetector, DNSAnomalyDetector
from .watchlist_detector import (
    CleartextProtocolDetector,
    OffensivePackageInstallDetector,
    SuspiciousHostDetector,
)
from .webmail_exfil_detector import WebmailExfilDetector

__all__ = [
    "BeaconingDetector",
    "CleartextProtocolDetector",
    "DNSAnomalyDetector",
    "ExfilRatioDetector",
    "LnkJumpListDetector",
    "NetworkDetector",
    "OffensivePackageInstallDetector",
    "RegistryDetector",
    "SuspiciousHostDetector",
    "WebmailExfilDetector",
]
