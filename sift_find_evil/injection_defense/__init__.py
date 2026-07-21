"""Prompt-injection defense for hostile evidence text.

Evidence text extracted from disks, memory, or network captures can contain
adversarial content crafted to manipulate an LLM analyst (role-token injection,
invisible/BIDI reordering, forged verdict JSON, sentinel-boundary breakouts).

This package sanitizes such text and wraps it in a nonce-keyed untrusted-content
sentinel so downstream LLM reasoning treats it strictly as data, never as
instructions. Reporting is counts-only: the raw hostile payload is never
re-emitted into findings metadata.
"""

from .sanitizer import (
    ScanResult,
    derive_session_nonce,
    detect_injection,
    finding_from_scan,
    scan_and_wrap,
)

__all__ = [
    "ScanResult",
    "derive_session_nonce",
    "detect_injection",
    "finding_from_scan",
    "scan_and_wrap",
]
