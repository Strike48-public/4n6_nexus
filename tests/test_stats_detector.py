"""Tests for stats-over-grouped-events detectors (beaconing, DNS anomaly)."""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest

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


def test_beaconing_detector_flags_uniform_cadence():
    # 8 events spaced every 300 seconds — textbook beacon.
    requests = [
        _http("evil.example.com", offset_seconds=i * 300.0) for i in range(8)
    ]
    findings = BeaconingDetector().analyze(http_requests=requests)
    assert len(findings) == 1
    ev = findings[0].evidence
    assert ev["host"] == "evil.example.com"
    assert ev["src_ip"] == "10.0.0.5"
    assert ev["event_count"] == 8
    assert ev["coefficient_of_variation"] < 0.01
    assert 290.0 < ev["mean_interval_seconds"] < 310.0


def test_beaconing_detector_ignores_jittery_browsing():
    # Wildly varying intervals — user browsing, not a beacon.
    offsets = [0, 35, 120, 300, 800, 810, 2000]
    requests = [
        _http("news.example.com", offset_seconds=o) for o in offsets
    ]
    findings = BeaconingDetector().analyze(http_requests=requests)
    assert findings == []


def test_beaconing_detector_ignores_below_min_events():
    requests = [
        _http("evil.example.com", offset_seconds=i * 300.0) for i in range(3)
    ]
    findings = BeaconingDetector().analyze(http_requests=requests)
    assert findings == []


def test_beaconing_detector_ignores_sub_threshold_mean():
    # Tight, regular, but sub-30s — TCP retries or asset loads, not a beacon.
    requests = [
        _http("cdn.example.com", offset_seconds=i * 2.0) for i in range(20)
    ]
    findings = BeaconingDetector().analyze(http_requests=requests)
    assert findings == []


def test_beaconing_detector_skips_non_configured_methods():
    requests = [
        _http("evil.example.com", offset_seconds=i * 300.0, method="POST")
        for i in range(8)
    ]
    findings = BeaconingDetector().analyze(http_requests=requests)
    assert findings == []


def test_beaconing_detector_normalizes_host_with_port():
    requests = [
        _http(f"evil.example.com:443", offset_seconds=i * 300.0)
        for i in range(6)
    ]
    findings = BeaconingDetector().analyze(http_requests=requests)
    assert len(findings) == 1
    assert findings[0].evidence["host"] == "evil.example.com"


def test_beaconing_detector_rejects_invalid_constructor_args():
    with pytest.raises(ValueError):
        BeaconingDetector(min_events=2)
    with pytest.raises(ValueError):
        BeaconingDetector(max_cov=0)


def test_beaconing_detector_handles_empty_input():
    assert BeaconingDetector().analyze(http_requests=None) == []
    assert BeaconingDetector().analyze(http_requests=[]) == []


# --- DNSAnomalyDetector ------------------------------------------------------


def test_dns_anomaly_flags_long_high_entropy_label():
    # base32-ish long label under attacker apex.
    name = "a7kd9f2mxq8bvn3wc5p1rz6j4hty0lugei7xqz3a4b5c6d7e8f9g0h1i.example.com"
    findings = DNSAnomalyDetector().analyze(dns_queries=[_dns(name)])
    assert len(findings) == 1
    ev = findings[0].evidence
    assert ev["apex_domain"] == "example.com"
    assert ev["longest_label_length"] >= 40
    assert ev["longest_label_entropy"] >= 3.5


def test_dns_anomaly_ignores_short_labels():
    findings = DNSAnomalyDetector().analyze(
        dns_queries=[_dns("www.google.com"), _dns("api.github.com")],
    )
    assert findings == []


def test_dns_anomaly_suppresses_aws_elb():
    name = (
        "internal-some-loadbalancer-1234567890abcdefghij"
        ".us-east-1.elb.amazonaws.com"
    )
    findings = DNSAnomalyDetector().analyze(dns_queries=[_dns(name)])
    assert findings == []


def test_dns_anomaly_suppresses_cloudfront():
    name = "d1234567890abcdefghijklmnopqrstuvwxyz.cloudfront.net"
    findings = DNSAnomalyDetector().analyze(dns_queries=[_dns(name)])
    assert findings == []


def test_dns_anomaly_honors_disable_cdn_suppression():
    name = "d1234567890abcdefghijklmnopqrstuvwxyz.cloudfront.net"
    findings = DNSAnomalyDetector(
        ignore_known_cdn_patterns=False
    ).analyze(dns_queries=[_dns(name)])
    # Only flagged if label is both long and high-entropy.
    # "d1234567890abcdefghijklmnopqrstuvwxyz" is 37 chars — under default 40.
    # Make sure the detector can still be configured to flag it.
    detector = DNSAnomalyDetector(
        ignore_known_cdn_patterns=False, min_label_length=20
    )
    findings = detector.analyze(dns_queries=[_dns(name)])
    assert len(findings) == 1


def test_dns_anomaly_groups_by_apex():
    names = [
        "a7kd9f2mxq8bvn3wc5p1rz6j4hty0lugei7xqz3a4b5c.evil.com",
        "p1rz6j4hty0lugei7xqz3a4b5c6d7e8f9g0h1i2j3kl.evil.com",
    ]
    findings = DNSAnomalyDetector().analyze(
        dns_queries=[_dns(n) for n in names],
    )
    assert len(findings) == 1
    assert findings[0].evidence["apex_domain"] == "evil.com"
    assert findings[0].evidence["query_count"] == 2


def test_dns_anomaly_encoding_hint_base32():
    # Long label of only base32 alphabet.
    label = "aqkzfnr47x2hsbuvw5yt3l6m" + "aqkzfnr47x2hsbuvw"  # 41 chars
    name = f"{label}.tunnel.example.com"
    findings = DNSAnomalyDetector().analyze(dns_queries=[_dns(name)])
    assert len(findings) == 1
    assert findings[0].evidence["encoding_hint"] == "base32"


def test_dns_anomaly_rejects_invalid_min_length():
    with pytest.raises(ValueError):
        DNSAnomalyDetector(min_label_length=5)


def test_dns_anomaly_handles_empty_input():
    assert DNSAnomalyDetector().analyze(dns_queries=None) == []
    assert DNSAnomalyDetector().analyze(dns_queries=[]) == []
