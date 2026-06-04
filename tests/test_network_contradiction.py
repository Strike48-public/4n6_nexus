"""Tests for the NETWORK contradiction type in the self-correction engine (SFE-q41).

The network contradiction is a genuine cross-artifact inconsistency:
a TCP conversation to a routable external IPv4 with *no preceding DNS query*
that resolved to that IP. Malware with a hardcoded C2 address skips DNS;
legitimate clients almost always resolve a hostname first (MITRE T1071 /
T1571 — hardcoded-IP command-and-control).

The self-correction loop mirrors the disk and memory patterns:

* DETECT: external-IP conversation with no resolving DNS query
  -> NETWORK_PRESENCE_MISMATCH
* RESOLVE: if the destination IP belongs to known-benign direct-IP
  infrastructure (NTP pool, public DNS resolvers) the contradiction is
  downgraded -> ``contradiction_resolved`` (legitimate direct-IP traffic).

These tests drive the engine path directly; the scenario harness never feeds
DNS / conversation data into the engine, so the F1=1.00 gate is untouched.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sift_find_evil.parsers.pcap_parser import DNSQuery, TCPConversation
from sift_find_evil.self_correction.contradiction_detector import (
    ContradictionDetector,
    ContradictionType,
    Severity,
)
from sift_find_evil.self_correction.engine import SelfCorrectionEngine
from sift_find_evil.findings.categories import FindingCategory


_T0 = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)


# --- fixtures -----------------------------------------------------------


def _conv(
    dst_ip: str, dst_port: int = 443, client_ip: str = "10.0.0.5"
) -> TCPConversation:
    """A conversation from an internal client to dst_ip on dst_port."""
    return TCPConversation(
        endpoint_a_ip=client_ip,
        endpoint_a_port=50111,
        endpoint_b_ip=dst_ip,
        endpoint_b_port=dst_port,
        frames_a_to_b=10,
        bytes_a_to_b=1000,
        frames_b_to_a=8,
        bytes_b_to_a=8000,
        total_frames=18,
        total_bytes=9000,
    )


def _dns(query_name: str, response_ip: str, src_ip: str = "10.0.0.5") -> DNSQuery:
    return DNSQuery(
        frame_number=1,
        timestamp=_T0,
        src_ip=src_ip,
        query_name=query_name,
        query_type="A",
        response_ip=response_ip,
    )


# --- detector-level: detect ---------------------------------------------


def test_external_conversation_without_dns_is_a_contradiction():
    """A conversation to an external IP never resolved by DNS is flagged."""
    detector = ContradictionDetector()
    conversations = [_conv("203.0.113.50")]
    dns = [_dns("good.example.com", "198.51.100.10")]  # unrelated resolution

    contradictions = detector.detect_network_presence_mismatch(
        tcp_conversations=conversations, dns_queries=dns
    )

    assert len(contradictions) == 1
    c = contradictions[0]
    assert c.type == ContradictionType.NETWORK_PRESENCE_MISMATCH
    assert c.severity == Severity.HIGH
    assert c.details["dst_ip"] == "203.0.113.50"
    assert c.confidence_impact < 0


def test_resolved_external_ip_is_not_flagged():
    """If DNS resolved the destination IP, there is no contradiction."""
    detector = ContradictionDetector()
    conversations = [_conv("203.0.113.50")]
    dns = [_dns("c2.example.com", "203.0.113.50")]  # this IP WAS resolved

    contradictions = detector.detect_network_presence_mismatch(
        tcp_conversations=conversations, dns_queries=dns
    )

    assert contradictions == []


def test_private_destination_is_not_flagged():
    """Internal/RFC1918 destinations are out of scope for hardcoded-C2."""
    detector = ContradictionDetector()
    conversations = [_conv("10.0.0.99"), _conv("192.168.1.10")]

    contradictions = detector.detect_network_presence_mismatch(
        tcp_conversations=conversations, dns_queries=[]
    )

    assert contradictions == []


def test_non_routable_reserved_ranges_are_not_flagged():
    """CGNAT, benchmarking, Class E, broadcast, etc. are not external."""
    detector = ContradictionDetector()
    conversations = [
        _conv("100.64.1.1"),  # CGNAT / RFC6598 shared address space
        _conv("198.18.0.5"),  # RFC2544 benchmarking
        _conv("240.0.0.1"),  # Class E / reserved
        _conv("0.0.0.1"),  # "this network"
        _conv("169.254.1.1"),  # link-local
        _conv("255.255.255.255"),  # limited broadcast
    ]

    contradictions = detector.detect_network_presence_mismatch(
        tcp_conversations=conversations, dns_queries=[]
    )

    assert contradictions == []


def test_malformed_ip_is_not_flagged():
    """A garbage endpoint string is skipped, not crashed on."""
    detector = ContradictionDetector()
    conversations = [_conv("not-an-ip"), _conv("")]

    contradictions = detector.detect_network_presence_mismatch(
        tcp_conversations=conversations, dns_queries=[]
    )

    assert contradictions == []


def test_loopback_and_ipv6_destinations_are_not_flagged():
    """Loopback and IPv6 destinations are excluded (no tuned policy yet)."""
    detector = ContradictionDetector()
    conversations = [
        _conv("127.0.0.1"),
        TCPConversation(
            endpoint_a_ip="10.0.0.5",
            endpoint_a_port=50111,
            endpoint_b_ip="2606:4700:4700::1111",
            endpoint_b_port=443,
            frames_a_to_b=1,
            bytes_a_to_b=100,
            frames_b_to_a=1,
            bytes_b_to_a=100,
            total_frames=2,
            total_bytes=200,
        ),
    ]

    contradictions = detector.detect_network_presence_mismatch(
        tcp_conversations=conversations, dns_queries=[]
    )

    assert contradictions == []


def test_each_external_ip_deduped_to_one_contradiction():
    """Multiple conversations to the same hardcoded IP collapse to one."""
    detector = ContradictionDetector()
    conversations = [
        _conv("203.0.113.50", dst_port=443),
        _conv("203.0.113.50", dst_port=8080),
        _conv("198.51.100.7", dst_port=4444),
    ]

    contradictions = detector.detect_network_presence_mismatch(
        tcp_conversations=conversations, dns_queries=[]
    )

    assert len(contradictions) == 2
    assert {c.details["dst_ip"] for c in contradictions} == {
        "203.0.113.50",
        "198.51.100.7",
    }


# --- detector-level: resolve --------------------------------------------


def test_known_benign_infra_is_marked_resolvable():
    """A direct-IP hit to known-benign infra is flagged as resolvable."""
    detector = ContradictionDetector()
    conversations = [_conv("8.8.8.8", dst_port=53)]  # Google public DNS

    contradictions = detector.detect_network_presence_mismatch(
        tcp_conversations=conversations, dns_queries=[]
    )

    assert len(contradictions) == 1
    assert contradictions[0].details["known_benign_infra"] is True


# --- engine-level: detect + resolve + score -----------------------------


def test_engine_emits_unresolved_network_finding():
    """Hardcoded external IP with no DNS and not benign -> unresolved."""
    engine = SelfCorrectionEngine()
    findings = engine.analyze(
        mft_entries=[],
        prefetch_entries=[],
        event_log_entries=[],
        tcp_conversations=[_conv("203.0.113.50", dst_port=4444)],
        dns_queries=[],
    )

    net = [
        f
        for f in findings
        if any(
            c.type == ContradictionType.NETWORK_PRESENCE_MISMATCH
            for c in f.contradictions
        )
    ]
    assert len(net) == 1
    finding = net[0]
    assert finding.category == FindingCategory.COMMAND_AND_CONTROL
    assert finding.resolutions == []
    assert "dns" in " ".join(finding.reasoning_chain).lower()


def test_engine_emits_resolved_network_finding_for_benign_infra():
    """Direct-IP to benign infra -> contradiction resolved (downgraded)."""
    engine = SelfCorrectionEngine()
    findings = engine.analyze(
        mft_entries=[],
        prefetch_entries=[],
        event_log_entries=[],
        tcp_conversations=[_conv("1.1.1.1", dst_port=53)],
        dns_queries=[],
    )

    net = [
        f
        for f in findings
        if any(
            c.type == ContradictionType.NETWORK_PRESENCE_MISMATCH
            for c in f.contradictions
        )
    ]
    assert len(net) == 1
    assert net[0].resolutions
    # Resolution recovers confidence above the unresolved floor
    assert net[0].confidence > 0.0


def test_engine_without_network_args_is_unchanged():
    """Default call (no network kwargs) emits no network findings."""
    engine = SelfCorrectionEngine()
    findings = engine.analyze(mft_entries=[], prefetch_entries=[], event_log_entries=[])
    assert all(
        not any(
            c.type == ContradictionType.NETWORK_PRESENCE_MISMATCH
            for c in f.contradictions
        )
        for f in findings
    )


# --- adapter-level: domain=network --------------------------------------


def test_network_finding_maps_to_network_domain_verification():
    """The verifier adapter reports domain=network for this contradiction."""
    from sift_find_evil.self_correction.verifier_adapter import (
        finding_to_verification,
    )

    engine = SelfCorrectionEngine()
    findings = engine.analyze(
        mft_entries=[],
        prefetch_entries=[],
        event_log_entries=[],
        tcp_conversations=[_conv("203.0.113.50", dst_port=4444)],
        dns_queries=[],
    )
    net = next(
        f
        for f in findings
        if any(
            c.type == ContradictionType.NETWORK_PRESENCE_MISMATCH
            for c in f.contradictions
        )
    )

    v = finding_to_verification(net, finding_id="F-NET-1")
    assert v.domain == "network"
    assert v.contradiction_type == "network_presence_mismatch"
    assert v.verdict == "contradiction_detected"
