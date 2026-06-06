"""Coverage-focused tests for watchlist_detector internal branches.

Targets previously-uncovered lines in SuspiciousHostDetector:
- HTTP host that does not match any watchlist (continue path).
- _categorize empty-host guard, DNS-SD/mDNS skip guard.
- _normalize_host protocol-scheme strip and trailing-port strip.

These complement tests/test_watchlist_detector.py and drive the private
helpers directly where the public path is otherwise hard to reach.
"""

from __future__ import annotations

from datetime import datetime

from sift_find_evil.detectors.watchlist_detector import SuspiciousHostDetector
from sift_find_evil.parsers.pcap_parser import DNSQuery, HTTPRequest


def _http(
    host: str, src: str = "10.0.0.1", ts: str = "2020-09-19T23:07:36"
) -> HTTPRequest:
    return HTTPRequest(
        frame_number=1,
        timestamp=datetime.fromisoformat(ts),
        src_ip=src,
        dst_ip="1.2.3.4",
        method="GET",
        host=host,
        uri="/",
    )


def _dns(name: str, src: str = "10.0.0.1", ts: str = "2020-09-19T22:54:08") -> DNSQuery:
    return DNSQuery(
        frame_number=1,
        timestamp=datetime.fromisoformat(ts),
        src_ip=src,
        query_name=name,
        query_type="A",
    )


# --- analyze() HTTP non-match branch (line 167) -----------------------------


def test_http_host_not_in_watchlist_is_skipped():
    """An HTTP request whose host is not on any watchlist hits the continue."""
    findings = SuspiciousHostDetector().analyze(
        dns_queries=None,
        http_requests=[_http("www.example.com"), _http("cdn.update.microsoft.com")],
    )
    assert findings == []


def test_http_match_alongside_non_match_emits_only_matches():
    """Mix matched + unmatched HTTP hosts: only the watchlisted one survives."""
    findings = SuspiciousHostDetector().analyze(
        http_requests=[_http("www.example.com"), _http("pastebin.com")],
    )
    assert len(findings) == 1
    assert findings[0].evidence["host"] == "pastebin.com"
    assert findings[0].evidence["watchlist_category"] == "paste_drops"


# --- _categorize empty-host guard (line 175) --------------------------------


def test_categorize_empty_host_returns_none():
    det = SuspiciousHostDetector()
    assert det._categorize("") is None


def test_analyze_empty_http_host_skipped():
    """Empty host string flows through analyze -> _categorize empty guard."""
    findings = SuspiciousHostDetector().analyze(http_requests=[_http("")])
    assert findings == []


# --- _categorize DNS-SD / mDNS skip guard (line 179) ------------------------


def test_categorize_skips_underscore_service_discovery_name():
    det = SuspiciousHostDetector()
    assert det._categorize("_http._tcp.pastebin.com") is None


def test_categorize_skips_underscore_prefixed_watchlist_suffix():
    """An underscore-prefixed name whose suffix is watchlisted is still skipped.

    Exercises the mDNS/DNS-SD guard (line 179) on the underscore branch, which is
    the only reachable arm of that condition (`.local` label can never satisfy
    `".local" in host.split(".")`).
    """
    det = SuspiciousHostDetector()
    assert det._categorize("_http._tcp.pastebin.com") is None


def test_analyze_skips_mdns_query_even_if_watchlisted_suffix():
    """A DNS-SD style name whose tail matches the watchlist is skipped, not emitted."""
    findings = SuspiciousHostDetector().analyze(
        dns_queries=[_dns("_sub._tcp.pastebin.com")],
    )
    assert findings == []


# --- _normalize_host scheme + port strip (lines 191, 194) -------------------


def test_normalize_host_strips_protocol_scheme():
    det = SuspiciousHostDetector()
    assert det._normalize_host("https://Pastebin.com/raw") == "pastebin.com"


def test_normalize_host_strips_trailing_port():
    det = SuspiciousHostDetector()
    assert det._normalize_host("pastebin.com:8443") == "pastebin.com"


def test_normalize_host_strips_scheme_and_port_together():
    det = SuspiciousHostDetector()
    assert det._normalize_host("http://pastebin.com:80/path") == "pastebin.com"


def test_normalize_host_strips_trailing_dot():
    det = SuspiciousHostDetector()
    assert det._normalize_host("pastebin.com.") == "pastebin.com"


def test_analyze_matches_host_with_scheme_and_port_via_normalize():
    """End-to-end: a URL-shaped host normalizes and matches the watchlist."""
    findings = SuspiciousHostDetector().analyze(
        http_requests=[_http("https://pastebin.com:443/raw/abc")],
    )
    assert len(findings) == 1
    assert findings[0].evidence["host"] == "pastebin.com"
