"""Tests for TCPConversation parsing from tshark -z conv,tcp output."""

from __future__ import annotations

from sift_find_evil.parsers.pcap_parser import PcapParser


SAMPLE = """================================================================================
TCP Conversations
Filter:<No Filter>
                                                           |       <-      | |       ->      | |     Total     |    Relative    |   Duration   |
                                                           | Frames  Bytes | | Frames  Bytes | | Frames  Bytes |      Start     |              |
156.59.33.57:33274         <-> 52.64.108.95:443             67364 100 MB      28312 1,881 kB    95676 102 MB      362.574972000        50.8843
156.59.33.44:46300         <-> 156.59.33.77:514              4171 275 kB       4174 1,086 kB     8345 1,362 kB      9.002285000     11280.9093
156.59.33.180:28179        <-> 44.226.54.40:443              100 40 kB         200 860 kB       300 900 kB      100.0                10.0
"""


def test_parse_tcp_conv_table_three_rows():
    rows = PcapParser._parse_tcp_conv_table(SAMPLE)
    assert len(rows) == 3


def test_parse_tcp_conv_preserves_endpoints():
    rows = PcapParser._parse_tcp_conv_table(SAMPLE)
    first = rows[0]
    assert first.endpoint_a_ip == "156.59.33.57"
    assert first.endpoint_a_port == 33274
    assert first.endpoint_b_ip == "52.64.108.95"
    assert first.endpoint_b_port == 443


def test_parse_tcp_conv_converts_units():
    rows = PcapParser._parse_tcp_conv_table(SAMPLE)
    # Row 0: <- 100 MB, -> 1,881 kB, total 102 MB
    assert rows[0].bytes_b_to_a == 100 * 1024 * 1024
    assert rows[0].bytes_a_to_b == 1881 * 1024
    assert rows[0].total_frames == 95676


def test_service_port_picks_well_known_side():
    rows = PcapParser._parse_tcp_conv_table(SAMPLE)
    assert rows[0].service_port() == 443   # :33274 <-> :443
    assert rows[1].service_port() == 514   # :46300 <-> :514
    assert rows[2].service_port() == 443


def test_parse_tcp_conv_skips_header_lines():
    rows = PcapParser._parse_tcp_conv_table(SAMPLE)
    for r in rows:
        assert r.total_frames > 0
        assert ":" not in r.endpoint_a_ip  # IPs don't have colons after split
