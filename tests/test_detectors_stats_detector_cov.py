"""Coverage-targeted tests for stats_detector branch/guard paths.

Owned exclusively by this file. Drives the specific uncovered lines:

- 87:  ``analyze`` skips a request whose host normalizes to empty.
- 117: ``_normalize_host`` returns "" for a falsy host.
- 120: ``_normalize_host`` strips a ``scheme://`` prefix.
- 245: ``analyze`` skips a long label whose Shannon entropy is below threshold.
- 269: ``_shannon_entropy`` returns 0.0 for an empty string.
- 336: ``_encoding_hint`` returns None for a non-base32/base64 label.
"""

from __future__ import annotations

from datetime import datetime, timedelta

from sift_find_evil.detectors.stats_detector import (
    BeaconingDetector,
    DNSAnomalyDetector,
)
from sift_find_evil.parsers.pcap_parser import DNSQuery, HTTPRequest


_BASE_TS = datetime(2020, 9, 19, 22, 0, 0)


def _http(
    host: str,
    offset_seconds: float,
    method: str = "CONNECT",
    src: str = "10.0.0.5",
) -> HTTPRequest:
    return HTTPRequest(
        frame_number=1,
        timestamp=_BASE_TS + timedelta(seconds=offset_seconds),
        src_ip=src,
        dst_ip="1.2.3.4",
        method=method,
        host=host,
        uri="/",
    )


def _dns(name: str, src: str = "10.0.0.5") -> DNSQuery:
    return DNSQuery(
        frame_number=1,
        timestamp=_BASE_TS,
        src_ip=src,
        query_name=name,
        query_type="A",
    )


# --- BeaconingDetector -------------------------------------------------------


def test_beaconing_analyze_skips_request_with_empty_host():
    """Line 87: a request whose host normalizes to empty is dropped.

    An empty host string passes the method filter but ``_normalize_host``
    returns "", so the ``if not host: continue`` guard fires and the request
    never enters a group. With only empty-host requests, no findings emit.
    """
    requests = [_http("", offset_seconds=i * 300.0) for i in range(8)]
    findings = BeaconingDetector().analyze(http_requests=requests)
    assert findings == []


def test_beaconing_analyze_empty_host_does_not_block_valid_host():
    """Empty-host requests are skipped (line 87) while a real beacon still fires."""
    requests = [_http("", offset_seconds=i * 50.0) for i in range(4)]
    requests += [_http("evil.example.com", offset_seconds=i * 300.0) for i in range(8)]
    findings = BeaconingDetector().analyze(http_requests=requests)
    assert len(findings) == 1
    assert findings[0].evidence["host"] == "evil.example.com"


def test_normalize_host_returns_empty_for_falsy_host():
    """Line 117: ``_normalize_host`` short-circuits to "" on a falsy host."""
    assert BeaconingDetector._normalize_host("") == ""


def test_normalize_host_strips_scheme_prefix():
    """Line 120: a ``scheme://`` prefix is stripped before path/port handling."""
    assert (
        BeaconingDetector._normalize_host("https://evil.example.com:443/path")
        == "evil.example.com"
    )


def test_beaconing_normalizes_scheme_prefixed_host_end_to_end():
    """Drive line 120 through the public analyze() path as well."""
    requests = [
        _http("http://beacon.example.com/", offset_seconds=i * 300.0) for i in range(6)
    ]
    findings = BeaconingDetector().analyze(http_requests=requests)
    assert len(findings) == 1
    assert findings[0].evidence["host"] == "beacon.example.com"


# --- DNSAnomalyDetector ------------------------------------------------------


def test_dns_anomaly_skips_long_but_low_entropy_label():
    """Line 245: a long label below the entropy threshold is not flagged.

    A 45-char label made of a single repeated character is long enough to pass
    the length gate but has Shannon entropy 0.0, well under min_entropy=3.5, so
    the ``continue`` on line 245 fires and no finding is produced.
    """
    low_entropy_label = "a" * 45
    name = f"{low_entropy_label}.example.com"
    findings = DNSAnomalyDetector().analyze(dns_queries=[_dns(name)])
    assert findings == []


def test_dns_anomaly_low_entropy_skipped_high_entropy_flagged():
    """Long low-entropy label is skipped (line 245); high-entropy one fires."""
    low = f"{'a' * 45}.boring.com"
    high = "a7kd9f2mxq8bvn3wc5p1rz6j4hty0lugei7xqz3a4b5c6d7.evil.com"
    findings = DNSAnomalyDetector().analyze(dns_queries=[_dns(low), _dns(high)])
    assert len(findings) == 1
    assert findings[0].evidence["apex_domain"] == "evil.com"


def test_shannon_entropy_returns_zero_for_empty_string():
    """Line 269: empty input yields 0.0 entropy with no log of zero."""
    assert DNSAnomalyDetector._shannon_entropy("") == 0.0


def test_encoding_hint_returns_none_for_plain_label():
    """Line 336: a label matching neither base32 nor base64 returns None.

    The label mixes upper/lower with hyphens (hyphen is not in either alphabet),
    so both regexes fail to match and the hint falls through to None.
    """
    assert (
        DNSAnomalyDetector._encoding_hint("Some-Mixed_Label-That!Matches?Neither")
        is None
    )


def test_dns_anomaly_finding_has_no_encoding_hint_for_mixed_label():
    """Drive line 336 through analyze(): a long high-entropy label that is not
    valid base32/base64 produces a finding with encoding_hint None."""
    # 45 chars, high entropy, contains a hyphen -> neither base32 nor base64.
    label = "ab1-cd2-ef3-gh4-ij5-kl6-mn7-op8-qr9-st0-uvwx"
    assert len(label) >= 40
    name = f"{label}.example.com"
    findings = DNSAnomalyDetector().analyze(dns_queries=[_dns(name)])
    assert len(findings) == 1
    assert findings[0].evidence["encoding_hint"] is None
