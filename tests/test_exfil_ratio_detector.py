"""Tests for ExfilRatioDetector (asymmetric outbound/inbound byte ratio)."""

from __future__ import annotations

from datetime import datetime

import pytest

from sift_find_evil.detectors.exfil_ratio_detector import ExfilRatioDetector
from sift_find_evil.findings import FindingCategory
from sift_find_evil.parsers.pcap_parser import DNSQuery, TCPConversation


def _conv(
    *,
    client_ip: str = "10.0.0.5",
    server_ip: str = "44.226.54.40",
    server_port: int = 443,
    bytes_out: int = 900_000,
    bytes_in: int = 40_000,
    client_port: int = 54321,
) -> TCPConversation:
    """Build a TCPConversation with A=client, B=server (matches the pcap_parser row order)."""
    return TCPConversation(
        endpoint_a_ip=client_ip,
        endpoint_a_port=client_port,
        endpoint_b_ip=server_ip,
        endpoint_b_port=server_port,
        frames_a_to_b=500,
        bytes_a_to_b=bytes_out,
        frames_b_to_a=200,
        bytes_b_to_a=bytes_in,
        total_frames=700,
        total_bytes=bytes_out + bytes_in,
    )


def _dns_response(name: str, ip: str) -> DNSQuery:
    return DNSQuery(
        frame_number=1,
        timestamp=datetime(2020, 9, 19, 22, 0, 0),
        src_ip="10.0.0.5",
        query_name=name,
        query_type="A",
        response_ip=ip,
    )


def test_flags_asymmetric_outbound_flow():
    findings = ExfilRatioDetector().analyze(
        tcp_conversations=[_conv(bytes_out=900_000, bytes_in=40_000)],
    )
    assert len(findings) == 1
    ev = findings[0].evidence
    assert ev["client_ip"] == "10.0.0.5"
    assert ev["server_ip"] == "44.226.54.40"
    assert ev["outbound_bytes"] == 900_000
    assert ev["inbound_bytes"] == 40_000
    assert ev["outbound_inbound_ratio"] == 22.5
    assert findings[0].category == FindingCategory.DATA_EXFILTRATION


def test_ignores_balanced_flow():
    findings = ExfilRatioDetector().analyze(
        tcp_conversations=[_conv(bytes_out=500_000, bytes_in=400_000)],
    )
    assert findings == []


def test_ignores_small_flow_even_with_high_ratio():
    # 100kB out, 1kB in would be 100x ratio — but under absolute floor.
    findings = ExfilRatioDetector().analyze(
        tcp_conversations=[_conv(bytes_out=100_000, bytes_in=1_000)],
    )
    assert findings == []


def test_ignores_inbound_heavy_flow():
    # Typical download: server sends MB, client sends a few kB.
    findings = ExfilRatioDetector().analyze(
        tcp_conversations=[_conv(bytes_out=50_000, bytes_in=5_000_000)],
    )
    assert findings == []


def test_ignores_non_data_port():
    # Port 9999 is outside the data-port list, so even a 10:1 ratio with
    # plenty of bytes should be skipped.
    findings = ExfilRatioDetector().analyze(
        tcp_conversations=[
            _conv(server_port=9999, bytes_out=1_000_000, bytes_in=50_000)
        ],
    )
    assert findings == []


def test_flags_flow_when_server_is_endpoint_a():
    # tshark can emit either endpoint as A. Detector must still identify the
    # server side by matching server_port.
    conv = TCPConversation(
        endpoint_a_ip="44.226.54.40",
        endpoint_a_port=443,
        endpoint_b_ip="10.0.0.5",
        endpoint_b_port=54321,
        frames_a_to_b=200,
        bytes_a_to_b=40_000,  # server -> client
        frames_b_to_a=500,
        bytes_b_to_a=900_000,  # client -> server
        total_frames=700,
        total_bytes=940_000,
    )
    findings = ExfilRatioDetector().analyze(tcp_conversations=[conv])
    assert len(findings) == 1
    ev = findings[0].evidence
    assert ev["client_ip"] == "10.0.0.5"
    assert ev["server_ip"] == "44.226.54.40"
    assert ev["outbound_bytes"] == 900_000
    assert ev["inbound_bytes"] == 40_000


def test_ip_literal_raises_confidence():
    # No DNS resolved to the destination IP -> IP-literal signal.
    findings = ExfilRatioDetector().analyze(
        tcp_conversations=[_conv(server_ip="44.226.54.40")],
        dns_queries=[_dns_response("example.com", "203.0.113.10")],
    )
    assert len(findings) == 1
    assert findings[0].evidence["ip_literal_connection"] is True
    assert findings[0].confidence >= 0.75


def test_resolved_ip_does_not_raise_confidence():
    findings = ExfilRatioDetector().analyze(
        tcp_conversations=[_conv(server_ip="44.226.54.40")],
        dns_queries=[_dns_response("c2.example.com", "44.226.54.40")],
    )
    assert len(findings) == 1
    assert findings[0].evidence["ip_literal_connection"] is False


def test_without_dns_stream_ip_literal_flag_is_false():
    # Detector shouldn't invent the IP-literal signal when it has no DNS data.
    findings = ExfilRatioDetector().analyze(
        tcp_conversations=[_conv()],
        dns_queries=None,
    )
    assert findings[0].evidence["ip_literal_connection"] is False


def test_rejects_invalid_constructor_args():
    with pytest.raises(ValueError):
        ExfilRatioDetector(min_ratio=1.0)
    with pytest.raises(ValueError):
        ExfilRatioDetector(min_outbound_bytes=0)


def test_handles_empty_input():
    assert ExfilRatioDetector().analyze(tcp_conversations=None) == []
    assert ExfilRatioDetector().analyze(tcp_conversations=[]) == []


def test_zero_inbound_bytes_does_not_divide_by_zero():
    # Client pushes data, server never responds (SYN-only / dropped).
    findings = ExfilRatioDetector().analyze(
        tcp_conversations=[_conv(bytes_out=600_000, bytes_in=0)],
    )
    assert len(findings) == 1
    assert findings[0].evidence["inbound_bytes"] == 0


def test_format_bytes_tb():
    """Test _fmt_bytes with terabyte values."""
    detector = ExfilRatioDetector()
    assert detector._fmt_bytes(5_000_000_000_000) == "4.5 TB"
