"""Tests for watchlist-match detectors (suspicious hosts, offensive packages,
cleartext protocols)."""

from __future__ import annotations

from datetime import datetime

from sift_find_evil.detectors.watchlist_detector import (
    CleartextProtocolDetector,
    OffensivePackageInstallDetector,
    SuspiciousHostDetector,
)
from sift_find_evil.parsers.pcap_parser import (
    DNSQuery,
    HTTPRequest,
    TCPConversation,
)


def _dns(name: str, src: str = "10.0.0.1", ts: str = "2020-09-19T22:54:08") -> DNSQuery:
    return DNSQuery(
        frame_number=1,
        timestamp=datetime.fromisoformat(ts),
        src_ip=src,
        query_name=name,
        query_type="A",
    )


def _http(
    host: str,
    uri: str = "/",
    method: str = "GET",
    src: str = "10.0.0.1",
    ts: str = "2020-09-19T23:07:36",
) -> HTTPRequest:
    return HTTPRequest(
        frame_number=1,
        timestamp=datetime.fromisoformat(ts),
        src_ip=src,
        dst_ip="1.2.3.4",
        method=method,
        host=host,
        uri=uri,
    )


def _conv(port: int, frames: int = 100) -> TCPConversation:
    return TCPConversation(
        endpoint_a_ip="10.0.0.1",
        endpoint_a_port=54321,
        endpoint_b_ip="10.0.0.77",
        endpoint_b_port=port,
        frames_a_to_b=frames // 2,
        bytes_a_to_b=1000,
        frames_b_to_a=frames // 2,
        bytes_b_to_a=500,
        total_frames=frames,
        total_bytes=1500,
    )


# --- SuspiciousHostDetector --------------------------------------------------


def test_suspicious_host_matches_pastebin():
    findings = SuspiciousHostDetector().analyze(
        dns_queries=[_dns("pastebin.com"), _dns("pastebin.com")],
        http_requests=None,
    )
    assert len(findings) == 1
    assert findings[0].evidence["watchlist_category"] == "paste_drops"
    assert findings[0].evidence["access_count"] == 2


def test_suspicious_host_matches_subdomain():
    findings = SuspiciousHostDetector().analyze(
        dns_queries=[_dns("null-byte.wonderhowto.com")],
    )
    assert len(findings) == 1
    assert findings[0].evidence["watchlist_category"] == "hacking_tutorials"


def test_suspicious_host_does_not_match_unrelated():
    findings = SuspiciousHostDetector().analyze(
        dns_queries=[_dns("www.google.com"), _dns("github.com")],
    )
    assert findings == []


def test_suspicious_host_merges_across_artifacts():
    findings = SuspiciousHostDetector().analyze(
        dns_queries=[_dns("pastebin.com", src="10.0.0.5")],
        http_requests=[_http("pastebin.com", src="10.0.0.5")],
    )
    assert len(findings) == 1
    assert findings[0].evidence["access_count"] == 2


# --- OffensivePackageInstallDetector ----------------------------------------


def test_offensive_package_detects_metasploit_deb():
    uri = (
        "/data/releases/metasploit-framework/apt/pool/main/m/"
        "metasploit-framework/metasploit-framework_6.0.8_amd64.deb"
    )
    findings = OffensivePackageInstallDetector().analyze(
        http_requests=[_http("downloads.metasploit.com", uri=uri)],
    )
    assert len(findings) == 1
    assert findings[0].evidence["package"] == "metasploit-framework"
    assert findings[0].evidence["matched_mirror"] is True


def test_offensive_package_detects_john_deb():
    findings = OffensivePackageInstallDetector().analyze(
        http_requests=[
            _http(
                "nz.archive.ubuntu.com",
                uri="/ubuntu/pool/main/j/john/john_1.8.0-2build1_amd64.deb",
            )
        ],
    )
    assert len(findings) == 1
    assert findings[0].evidence["package"] == "john"


def test_offensive_package_ignores_non_get():
    findings = OffensivePackageInstallDetector().analyze(
        http_requests=[
            _http(
                "downloads.metasploit.com",
                uri="/pool/main/metasploit-framework_6.0.8_amd64.deb",
                method="CONNECT",
            )
        ],
    )
    assert findings == []


def test_offensive_package_ignores_benign_packages():
    findings = OffensivePackageInstallDetector().analyze(
        http_requests=[
            _http(
                "nz.archive.ubuntu.com",
                uri="/ubuntu/pool/main/p/python2.7/python2.7_2.7.17_amd64.deb",
            )
        ],
    )
    assert findings == []


def test_offensive_package_mirror_match_with_port():
    # Regression: `host.lower().rstrip(":0123456789")` would strip trailing
    # digits from any hostname, not just port suffixes — so "downloads.meta
    # sploit.com:443" used to become "downloads.metasploit.com" but also
    # "mirror1.example.com" would become "mirror.example.com". Verify the
    # port-only strip is correct.
    findings = OffensivePackageInstallDetector().analyze(
        http_requests=[
            _http(
                "downloads.metasploit.com:80",
                uri="/pool/main/metasploit-framework_6.0.8_amd64.deb",
            )
        ],
    )
    assert len(findings) == 1
    assert findings[0].evidence["matched_mirror"] is True


def test_offensive_package_does_not_truncate_numeric_hostnames():
    # Hostname ending in a digit must NOT match mirror list via digit-strip.
    findings = OffensivePackageInstallDetector(
        offensive_mirrors=("example.com",),
        package_names=("nonexistentpkg",),
    ).analyze(
        http_requests=[
            _http(
                "mirror1.example.com9",
                uri="/some/path.deb",
            )
        ],
    )
    # No package match AND the mirror match must not succeed by stripping "9".
    assert findings == []


# --- CleartextProtocolDetector ----------------------------------------------


def test_cleartext_detector_flags_syslog():
    findings = CleartextProtocolDetector().analyze(
        tcp_conversations=[_conv(514, frames=7768)],
    )
    assert len(findings) == 1
    assert findings[0].evidence["port"] == 514
    assert "Syslog" in findings[0].evidence["protocol_label"]


def test_cleartext_detector_ignores_tls_ports():
    findings = CleartextProtocolDetector().analyze(
        tcp_conversations=[_conv(443, frames=10000), _conv(22, frames=10000)],
    )
    assert findings == []


def test_cleartext_detector_respects_min_frames():
    findings = CleartextProtocolDetector(min_frames=100).analyze(
        tcp_conversations=[_conv(143, frames=3)],
    )
    assert findings == []


def test_cleartext_detector_ignores_bare_http():
    findings = CleartextProtocolDetector().analyze(
        tcp_conversations=[_conv(80, frames=10000)],
    )
    assert findings == []
