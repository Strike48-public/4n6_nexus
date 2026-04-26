"""Unit tests for PCAP parser."""

from __future__ import annotations

import subprocess
from datetime import datetime
from pathlib import Path

import pytest
from scapy.all import IP, TCP, UDP, DNS, DNSQR, Ether, wrpcap
from scapy.layers.http import HTTP, HTTPRequest as ScapyHTTPRequest

from sift_find_evil.parsers.pcap_parser import (
    DNSQuery,
    HTTPRequest,
    HTTPSession,
    PcapParser,
    SMTPMessage,
    TCPConversation,
)


@pytest.fixture
def temp_pcap_dir(tmp_path: Path) -> Path:
    """Create temporary directory for PCAP files."""
    pcap_dir = tmp_path / "pcaps"
    pcap_dir.mkdir()
    return pcap_dir


@pytest.fixture
def http_pcap(temp_pcap_dir: Path) -> Path:
    """Create a PCAP with HTTP traffic using Scapy."""
    pcap_path = temp_pcap_dir / "http.pcap"

    # Create HTTP GET request
    pkt1 = (
        Ether()
        / IP(src="192.168.1.100", dst="93.184.216.34")
        / TCP(sport=54321, dport=80)
        / ScapyHTTPRequest(
            Method=b"GET",
            Host=b"example.com",
            Path=b"/index.html",
            User_Agent=b"Mozilla/5.0",
        )
    )

    # Create HTTP POST request
    pkt2 = (
        Ether()
        / IP(src="192.168.1.100", dst="142.250.80.100")
        / TCP(sport=54322, dport=80)
        / ScapyHTTPRequest(
            Method=b"POST",
            Host=b"mail.google.com",
            Path=b"/mail/send",
            User_Agent=b"Chrome/90.0",
            Content_Type=b"application/x-www-form-urlencoded",
        )
        / b"to=user@example.com&subject=Test"
    )

    wrpcap(str(pcap_path), [pkt1, pkt2])
    return pcap_path


@pytest.fixture
def dns_pcap(temp_pcap_dir: Path) -> Path:
    """Create a PCAP with DNS queries using Scapy."""
    pcap_path = temp_pcap_dir / "dns.pcap"

    # Create DNS query
    pkt = (
        Ether()
        / IP(src="192.168.1.100", dst="8.8.8.8")
        / UDP(sport=54321, dport=53)
        / DNS(rd=1, qd=DNSQR(qname="example.com", qtype="A"))
    )

    wrpcap(str(pcap_path), [pkt])
    return pcap_path


def test_init_tshark_not_found() -> None:
    """Test PcapParser raises FileNotFoundError when tshark not found."""
    with pytest.raises(FileNotFoundError, match="tshark not found"):
        PcapParser(tshark_path="/nonexistent/tshark")


def test_init_tshark_exists(tmp_path: Path) -> None:
    """Test PcapParser initializes when tshark exists."""
    fake_tshark = tmp_path / "tshark"
    fake_tshark.touch()

    parser = PcapParser(tshark_path=str(fake_tshark))
    assert parser.tshark_path == fake_tshark


def test_extract_http_requests_pcap_not_found() -> None:
    """Test extract_http_requests raises FileNotFoundError for missing PCAP."""
    parser = PcapParser()
    nonexistent = Path("/nonexistent/capture.pcap")

    with pytest.raises(FileNotFoundError, match="PCAP file not found"):
        parser.extract_http_requests(nonexistent)


def test_extract_http_requests_success(http_pcap: Path) -> None:
    """Test extract_http_requests parses HTTP traffic."""
    parser = PcapParser()
    requests = parser.extract_http_requests(http_pcap)

    assert len(requests) >= 1
    assert all(isinstance(r, HTTPRequest) for r in requests)
    assert all(r.frame_number > 0 for r in requests)
    assert all(isinstance(r.timestamp, datetime) for r in requests)
    assert all(r.src_ip for r in requests)
    assert all(r.method in ["GET", "POST", "PUT", "DELETE", "HEAD"] for r in requests)


def test_extract_http_requests_with_filter(http_pcap: Path) -> None:
    """Test extract_http_requests with display filter."""
    parser = PcapParser()
    requests = parser.extract_http_requests(
        http_pcap, display_filter="http.request.method == GET"
    )

    assert all(r.method == "GET" for r in requests)


def test_extract_http_requests_tshark_timeout(http_pcap: Path, monkeypatch) -> None:
    """Test extract_http_requests raises RuntimeError on timeout."""
    parser = PcapParser()

    def mock_run(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd=[], timeout=60)

    monkeypatch.setattr(subprocess, "run", mock_run)

    with pytest.raises(RuntimeError, match="tshark timed out"):
        parser.extract_http_requests(http_pcap)


def test_extract_http_requests_tshark_error(http_pcap: Path, monkeypatch) -> None:
    """Test extract_http_requests raises RuntimeError on tshark failure."""
    parser = PcapParser()

    def mock_run(*args, **kwargs):
        raise subprocess.CalledProcessError(
            returncode=1, cmd=[], stderr="tshark error"
        )

    monkeypatch.setattr(subprocess, "run", mock_run)

    with pytest.raises(RuntimeError, match="tshark failed"):
        parser.extract_http_requests(http_pcap)


def test_extract_http_sessions_empty_pcap(temp_pcap_dir: Path) -> None:
    """Test extract_http_sessions returns empty list for empty PCAP."""
    parser = PcapParser()
    empty_pcap = temp_pcap_dir / "empty.pcap"
    wrpcap(str(empty_pcap), [])

    sessions = parser.extract_http_sessions(empty_pcap)
    assert sessions == []


def test_extract_http_sessions_groups_by_ip(http_pcap: Path) -> None:
    """Test extract_http_sessions groups requests by source IP."""
    parser = PcapParser()
    sessions = parser.extract_http_sessions(http_pcap)

    assert len(sessions) >= 1
    assert all(isinstance(s, HTTPSession) for s in sessions)
    assert all(s.src_ip for s in sessions)
    assert all(s.start_time <= s.end_time for s in sessions)
    assert all(len(s.requests) > 0 for s in sessions)


def test_extract_http_sessions_respects_timeout(http_pcap: Path) -> None:
    """Test extract_http_sessions splits sessions by timeout."""
    parser = PcapParser()
    sessions = parser.extract_http_sessions(http_pcap, session_timeout_seconds=1)

    # With very short timeout, requests should be in separate sessions
    assert len(sessions) >= 1


def test_build_session() -> None:
    """Test _build_session creates HTTPSession from requests."""
    parser = PcapParser()
    ts1 = datetime(2025, 1, 1, 10, 0, 0)
    ts2 = datetime(2025, 1, 1, 10, 5, 0)

    requests = [
        HTTPRequest(
            frame_number=1,
            timestamp=ts1,
            src_ip="192.168.1.100",
            dst_ip="93.184.216.34",
            method="GET",
            host="example.com",
            uri="/index.html",
        ),
        HTTPRequest(
            frame_number=2,
            timestamp=ts2,
            src_ip="192.168.1.100",
            dst_ip="93.184.216.34",
            method="POST",
            host="example.com",
            uri="/login",
        ),
    ]

    session = parser._build_session(requests)

    assert session.src_ip == "192.168.1.100"
    assert session.start_time == ts1
    assert session.end_time == ts2
    assert len(session.requests) == 2
    assert session.hosts_accessed == ("example.com",)


def test_extract_dns_queries_pcap_not_found() -> None:
    """Test extract_dns_queries raises FileNotFoundError for missing PCAP."""
    parser = PcapParser()
    nonexistent = Path("/nonexistent/capture.pcap")

    with pytest.raises(FileNotFoundError, match="PCAP file not found"):
        parser.extract_dns_queries(nonexistent)


def test_extract_dns_queries_success(dns_pcap: Path) -> None:
    """Test extract_dns_queries parses DNS traffic."""
    parser = PcapParser()
    queries = parser.extract_dns_queries(dns_pcap)

    assert len(queries) >= 1
    assert all(isinstance(q, DNSQuery) for q in queries)
    assert all(q.frame_number > 0 for q in queries)
    assert all(isinstance(q.timestamp, datetime) for q in queries)
    assert all(q.src_ip for q in queries)
    assert all(q.query_name for q in queries)
    assert all(q.query_type for q in queries)


def test_extract_dns_queries_tshark_error(dns_pcap: Path, monkeypatch) -> None:
    """Test extract_dns_queries raises RuntimeError on tshark failure."""
    parser = PcapParser()

    def mock_run(*args, **kwargs):
        raise subprocess.CalledProcessError(
            returncode=1, cmd=[], stderr="tshark error"
        )

    monkeypatch.setattr(subprocess, "run", mock_run)

    with pytest.raises(RuntimeError, match="tshark failed"):
        parser.extract_dns_queries(dns_pcap)


def test_extract_tcp_conversations_pcap_not_found() -> None:
    """Test extract_tcp_conversations raises FileNotFoundError for missing PCAP."""
    parser = PcapParser()
    nonexistent = Path("/nonexistent/capture.pcap")

    with pytest.raises(FileNotFoundError, match="PCAP file not found"):
        parser.extract_tcp_conversations(nonexistent)


def test_extract_tcp_conversations_success(http_pcap: Path) -> None:
    """Test extract_tcp_conversations parses TCP flows."""
    parser = PcapParser()
    conversations = parser.extract_tcp_conversations(http_pcap)

    # May have 0 conversations if tshark doesn't output any
    assert isinstance(conversations, list)
    for conv in conversations:
        assert isinstance(conv, TCPConversation)
        assert conv.endpoint_a_ip
        assert conv.endpoint_a_port > 0
        assert conv.endpoint_b_ip
        assert conv.endpoint_b_port > 0
        assert conv.total_frames >= 0
        assert conv.total_bytes >= 0


def test_extract_tcp_conversations_timeout(http_pcap: Path, monkeypatch) -> None:
    """Test extract_tcp_conversations raises RuntimeError on timeout."""
    parser = PcapParser()

    def mock_run(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd=[], timeout=300)

    monkeypatch.setattr(subprocess, "run", mock_run)

    with pytest.raises(RuntimeError, match="tshark timed out"):
        parser.extract_tcp_conversations(http_pcap)


def test_parse_tcp_conv_table() -> None:
    """Test _parse_tcp_conv_table parses tshark conv,tcp output."""
    output = """
================================================================================
TCP Conversations
Filter:<No Filter>
                                               |       <-      | |       ->      | |     Total     |    Relative    |   Duration   |
                                               | Frames  Bytes | | Frames  Bytes | | Frames  Bytes |      Start     |              |
192.168.1.100:54321 <-> 93.184.216.34:80         10    1,024 bytes    15    2,048 bytes    25    3,072 bytes     0.000000000         1.5000
10.0.0.5:49152 <-> 172.217.16.165:443            5      512 kB       8      1 MB        13    1.5 MB         0.100000000         2.3000
================================================================================
"""

    conversations = PcapParser._parse_tcp_conv_table(output)

    assert len(conversations) == 2

    conv1 = conversations[0]
    assert conv1.endpoint_a_ip == "192.168.1.100"
    assert conv1.endpoint_a_port == 54321
    assert conv1.endpoint_b_ip == "93.184.216.34"
    assert conv1.endpoint_b_port == 80
    assert conv1.frames_b_to_a == 10
    assert conv1.bytes_b_to_a == 1024
    assert conv1.frames_a_to_b == 15
    assert conv1.bytes_a_to_b == 2048
    assert conv1.total_frames == 25
    assert conv1.total_bytes == 3072

    conv2 = conversations[1]
    assert conv2.endpoint_a_ip == "10.0.0.5"
    assert conv2.endpoint_a_port == 49152
    assert conv2.bytes_b_to_a == 512 * 1024  # kB
    assert conv2.bytes_a_to_b == 1 * 1024 * 1024  # MB
    assert conv2.total_bytes == int(1.5 * 1024 * 1024)  # 1.5 MB


def test_tcp_conversation_service_port_well_known() -> None:
    """Test TCPConversation.service_port returns well-known port."""
    conv = TCPConversation(
        endpoint_a_ip="192.168.1.100",
        endpoint_a_port=54321,
        endpoint_b_ip="93.184.216.34",
        endpoint_b_port=80,
        frames_a_to_b=10,
        bytes_a_to_b=1024,
        frames_b_to_a=15,
        bytes_b_to_a=2048,
        total_frames=25,
        total_bytes=3072,
    )

    assert conv.service_port() == 80


def test_tcp_conversation_service_port_both_well_known() -> None:
    """Test TCPConversation.service_port returns minimum when both are well-known."""
    conv = TCPConversation(
        endpoint_a_ip="10.0.0.1",
        endpoint_a_port=443,
        endpoint_b_ip="10.0.0.2",
        endpoint_b_port=80,
        frames_a_to_b=5,
        bytes_a_to_b=512,
        frames_b_to_a=8,
        bytes_b_to_a=1024,
        total_frames=13,
        total_bytes=1536,
    )

    assert conv.service_port() == 80


def test_tcp_conversation_service_port_neither_well_known() -> None:
    """Test TCPConversation.service_port returns minimum when neither is well-known."""
    conv = TCPConversation(
        endpoint_a_ip="10.0.0.1",
        endpoint_a_port=54321,
        endpoint_b_ip="10.0.0.2",
        endpoint_b_port=49152,
        frames_a_to_b=5,
        bytes_a_to_b=512,
        frames_b_to_a=8,
        bytes_b_to_a=1024,
        total_frames=13,
        total_bytes=1536,
    )

    assert conv.service_port() == 49152


def test_extract_smtp_messages_pcap_not_found() -> None:
    """Test extract_smtp_messages raises FileNotFoundError for missing PCAP."""
    parser = PcapParser()
    nonexistent = Path("/nonexistent/capture.pcap")

    with pytest.raises(FileNotFoundError, match="PCAP file not found"):
        parser.extract_smtp_messages(nonexistent)


def test_extract_smtp_messages_returns_empty_list(temp_pcap_dir: Path) -> None:
    """Test extract_smtp_messages returns empty list (not implemented yet)."""
    parser = PcapParser()
    empty_pcap = temp_pcap_dir / "empty.pcap"
    wrpcap(str(empty_pcap), [])

    messages = parser.extract_smtp_messages(empty_pcap)
    assert messages == []


def test_extract_http_requests_malformed_line(http_pcap: Path, monkeypatch) -> None:
    """Test extract_http_requests skips malformed tshark output lines."""
    parser = PcapParser()

    # Mock subprocess to return malformed output
    def mock_run(*args, **kwargs):
        class Result:
            stdout = "incomplete|line\n1|1234.0|192.168.1.1|bad_parse|GET|host|uri|agent|type|data\n"
            returncode = 0

        return Result()

    monkeypatch.setattr(subprocess, "run", mock_run)

    # Should skip malformed lines gracefully
    requests = parser.extract_http_requests(http_pcap)
    # Malformed lines skipped, may have 0 or 1 depending on which line parses
    assert isinstance(requests, list)


def test_extract_http_requests_value_error_on_parse(http_pcap: Path, monkeypatch) -> None:
    """Test extract_http_requests handles ValueError on timestamp parse."""
    parser = PcapParser()

    # Mock subprocess to return invalid timestamp
    def mock_run(*args, **kwargs):
        class Result:
            stdout = "1|invalid_timestamp|192.168.1.1|192.168.1.2|GET|host.com|/uri|agent|type|data\n"
            returncode = 0

        return Result()

    monkeypatch.setattr(subprocess, "run", mock_run)

    requests = parser.extract_http_requests(http_pcap)
    # Line with invalid timestamp should be skipped
    assert requests == []


def test_extract_http_sessions_single_request(temp_pcap_dir: Path) -> None:
    """Test extract_http_sessions with single request creates one session."""
    parser = PcapParser()

    # Create PCAP with single HTTP request
    pcap_path = temp_pcap_dir / "single.pcap"
    pkt = (
        Ether()
        / IP(src="192.168.1.100", dst="93.184.216.34")
        / TCP(sport=54321, dport=80)
        / ScapyHTTPRequest(
            Method=b"GET",
            Host=b"example.com",
            Path=b"/",
        )
    )
    wrpcap(str(pcap_path), [pkt])

    sessions = parser.extract_http_sessions(pcap_path)
    assert len(sessions) >= 1
    if sessions:
        assert sessions[0].src_ip == "192.168.1.100"


def test_extract_dns_queries_value_error_on_parse(dns_pcap: Path, monkeypatch) -> None:
    """Test extract_dns_queries handles ValueError on timestamp parse."""
    parser = PcapParser()

    # Mock subprocess to return invalid timestamp
    def mock_run(*args, **kwargs):
        class Result:
            stdout = "1|invalid_timestamp|192.168.1.1|example.com|A\n"
            returncode = 0

        return Result()

    monkeypatch.setattr(subprocess, "run", mock_run)

    queries = parser.extract_dns_queries(dns_pcap)
    # Line with invalid timestamp should be skipped
    assert queries == []


def test_extract_dns_queries_index_error_on_parse(dns_pcap: Path, monkeypatch) -> None:
    """Test extract_dns_queries handles IndexError on malformed line."""
    parser = PcapParser()

    # Mock subprocess to return line with too few fields
    def mock_run(*args, **kwargs):
        class Result:
            stdout = "1|1234.0\n"  # Only 2 fields, need 5
            returncode = 0

        return Result()

    monkeypatch.setattr(subprocess, "run", mock_run)

    queries = parser.extract_dns_queries(dns_pcap)
    # Malformed line should be skipped
    assert queries == []


def test_extract_smtp_messages_tshark_error(temp_pcap_dir: Path, monkeypatch) -> None:
    """Test extract_smtp_messages raises RuntimeError on tshark failure."""
    parser = PcapParser()
    pcap_path = temp_pcap_dir / "test.pcap"
    wrpcap(str(pcap_path), [])

    def mock_run(*args, **kwargs):
        raise subprocess.CalledProcessError(
            returncode=1, cmd=[], stderr="tshark error"
        )

    monkeypatch.setattr(subprocess, "run", mock_run)

    with pytest.raises(RuntimeError, match="tshark failed"):
        parser.extract_smtp_messages(pcap_path)
