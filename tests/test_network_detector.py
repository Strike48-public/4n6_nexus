"""Tests for network detector orchestrator."""

from unittest.mock import Mock

import pytest

from sift_find_evil.detectors.network_detector import NetworkDetector
from sift_find_evil.parsers.browser_history_parser import BrowserHistoryEntry
from sift_find_evil.parsers.pcap_parser import DNSQuery, HTTPRequest, TCPConversation


@pytest.fixture
def network_detector():
    """Create a NetworkDetector with mocked sub-detectors."""
    detector = NetworkDetector()

    # Mock all sub-detectors to return empty findings
    detector.webmail_exfil.analyze = Mock(return_value=[])
    detector.cloud_upload.analyze = Mock(return_value=[])
    detector.suspicious_host.analyze = Mock(return_value=[])
    detector.offensive_package.analyze = Mock(return_value=[])
    detector.cleartext_protocol.analyze = Mock(return_value=[])
    detector.beaconing.analyze = Mock(return_value=[])
    detector.dns_anomaly.analyze = Mock(return_value=[])
    detector.exfil_ratio.analyze = Mock(return_value=[])

    return detector


def test_analyze_with_browser_history(network_detector):
    """Test analyze with browser history triggers webmail and cloud detectors."""
    history = [
        BrowserHistoryEntry(
            timestamp=1234567890.0,
            url="https://mail.google.com",
            title="Gmail",
            visit_count=5,
            browser="chrome",
            profile="Default",
        )
    ]

    findings = network_detector.analyze(browser_history=history)

    assert network_detector.webmail_exfil.analyze.called
    assert network_detector.cloud_upload.analyze.called
    assert findings == []  # Mock returns empty list


def test_analyze_with_dns_queries(network_detector):
    """Test analyze with DNS queries triggers dns_anomaly and suspicious_host."""
    from datetime import datetime

    dns = [
        DNSQuery(
            frame_number=1,
            timestamp=datetime.fromtimestamp(1234567890.0),
            src_ip="192.168.1.100",
            query_name="evil.com",
            query_type="A",
            response_ip="1.2.3.4",
        )
    ]

    findings = network_detector.analyze(dns_queries=dns)

    assert network_detector.dns_anomaly.analyze.called
    assert network_detector.suspicious_host.analyze.called
    assert findings == []


def test_analyze_with_http_requests(network_detector):
    """Test analyze with HTTP requests triggers multiple detectors."""
    from datetime import datetime

    http = [
        HTTPRequest(
            frame_number=1,
            timestamp=datetime.fromtimestamp(1234567890.0),
            src_ip="192.168.1.100",
            dst_ip="1.2.3.4",
            method="GET",
            host="example.com",
            uri="/index.html",
            user_agent="Mozilla/5.0",
            content_type=None,
            form_data=None,
        )
    ]

    findings = network_detector.analyze(http_requests=http)

    assert network_detector.offensive_package.analyze.called
    assert network_detector.beaconing.analyze.called
    assert network_detector.suspicious_host.analyze.called
    assert findings == []


def test_analyze_with_tcp_conversations(network_detector):
    """Test analyze with TCP conversations triggers cleartext and exfil detectors."""
    tcp = [
        TCPConversation(
            endpoint_a_ip="192.168.1.100",
            endpoint_a_port=54321,
            endpoint_b_ip="1.2.3.4",
            endpoint_b_port=80,
            frames_a_to_b=10,
            bytes_a_to_b=1024,
            frames_b_to_a=15,
            bytes_b_to_a=2048,
            total_frames=25,
            total_bytes=3072,
        )
    ]

    findings = network_detector.analyze(tcp_conversations=tcp)

    assert network_detector.cleartext_protocol.analyze.called
    assert network_detector.exfil_ratio.analyze.called
    assert findings == []


def test_analyze_with_none_artifacts(network_detector):
    """Test analyze with all None artifacts does not crash."""
    findings = network_detector.analyze()

    assert findings == []
    assert not network_detector.webmail_exfil.analyze.called
    assert not network_detector.dns_anomaly.analyze.called
    assert not network_detector.offensive_package.analyze.called
    assert not network_detector.cleartext_protocol.analyze.called


def test_analyze_with_empty_lists(network_detector):
    """Test analyze with empty artifact lists still triggers detectors."""
    findings = network_detector.analyze(
        browser_history=[],
        dns_queries=[],
        http_requests=[],
        tcp_conversations=[],
    )

    assert findings == []
    assert network_detector.webmail_exfil.analyze.called
    assert network_detector.dns_anomaly.analyze.called
    assert network_detector.offensive_package.analyze.called
    assert network_detector.cleartext_protocol.analyze.called


def test_constructor_accepts_custom_detectors():
    """Test constructor accepts custom sub-detector instances."""
    mock_webmail = Mock()
    mock_cloud = Mock()

    detector = NetworkDetector(
        webmail_exfil=mock_webmail,
        cloud_upload=mock_cloud,
    )

    assert detector.webmail_exfil is mock_webmail
    assert detector.cloud_upload is mock_cloud
    assert detector.suspicious_host is not None  # Default instance
