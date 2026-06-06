"""Coverage-focused unit tests for ``sift_find_evil.parsers.pcap_parser``.

Targets three previously-uncovered branches without depending on scapy or a
real ``tshark`` binary:

* line 308 - ``extract_http_sessions`` saving the previous session when a new
  session starts (source-IP / timeout transition).
* line 382 - ``extract_dns_queries`` skipping a blank line in tshark output.
* line 436 - ``extract_tcp_conversations`` mapping a tshark
  ``CalledProcessError`` to a ``RuntimeError``.

These drive the parser by pointing it at a fake ``tshark`` file (so the
constructor's existence check passes) and monkeypatching ``subprocess.run``
to feed synthetic stdout / errors, mirroring the existing test_pcap_parser.py
style.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from sift_find_evil.parsers.pcap_parser import DNSQuery, HTTPSession, PcapParser


@pytest.fixture
def parser(tmp_path: Path) -> PcapParser:
    """A PcapParser pointed at a fake tshark binary that exists on disk."""
    fake_tshark = tmp_path / "tshark"
    fake_tshark.touch()
    return PcapParser(tshark_path=str(fake_tshark))


@pytest.fixture
def pcap_file(tmp_path: Path) -> Path:
    """An existing (content-irrelevant) PCAP path; tshark is always mocked."""
    pcap = tmp_path / "capture.pcap"
    pcap.write_bytes(b"\xd4\xc3\xb2\xa1")  # token bytes; never actually parsed
    return pcap


def _stdout_runner(stdout: str):
    """Return a subprocess.run replacement yielding fixed stdout."""

    def _run(*args, **kwargs):
        class Result:
            pass

        result = Result()
        result.stdout = stdout
        result.returncode = 0
        return result

    return _run


def test_extract_http_sessions_saves_previous_on_new_ip(
    parser: PcapParser, pcap_file: Path, monkeypatch
) -> None:
    """Line 308: a source-IP change flushes the prior session before starting a new one.

    Two requests from distinct source IPs at the same epoch force the loop to
    save the first session (current_session_requests non-empty) when the second
    request opens a new session, producing two HTTPSession objects.
    """
    stdout = (
        "1|1700000000.0|10.0.0.1|10.0.0.9|GET|a.example|/one|agent|type|data\n"
        "2|1700000001.0|10.0.0.2|10.0.0.9|GET|b.example|/two|agent|type|data\n"
    )
    monkeypatch.setattr(subprocess, "run", _stdout_runner(stdout))

    sessions = parser.extract_http_sessions(pcap_file)

    assert len(sessions) == 2
    assert all(isinstance(s, HTTPSession) for s in sessions)
    src_ips = sorted(s.src_ip for s in sessions)
    assert src_ips == ["10.0.0.1", "10.0.0.2"]


def test_extract_http_sessions_saves_previous_on_timeout(
    parser: PcapParser, pcap_file: Path, monkeypatch
) -> None:
    """Line 308 (timeout branch): same IP but a gap > timeout flushes the prior session."""
    # Same source IP, 1000s apart -> exceeds default 300s timeout -> two sessions.
    stdout = (
        "1|1700000000.0|10.0.0.1|10.0.0.9|GET|a.example|/one|agent|type|data\n"
        "2|1700001000.0|10.0.0.1|10.0.0.9|GET|b.example|/two|agent|type|data\n"
    )
    monkeypatch.setattr(subprocess, "run", _stdout_runner(stdout))

    sessions = parser.extract_http_sessions(pcap_file)

    assert len(sessions) == 2
    assert all(s.src_ip == "10.0.0.1" for s in sessions)


def test_extract_dns_queries_skips_blank_line(
    parser: PcapParser, pcap_file: Path, monkeypatch
) -> None:
    """Line 382: a blank line embedded in tshark output is skipped via ``continue``."""
    # Leading/trailing whitespace is stripped by the parser; an interior blank
    # line survives the split and exercises the ``if not line: continue`` guard.
    stdout = (
        "1|1700000000.0|10.0.0.1|example.com|A\n"
        "\n"
        "2|1700000001.0|10.0.0.2|other.com|AAAA\n"
    )
    monkeypatch.setattr(subprocess, "run", _stdout_runner(stdout))

    queries = parser.extract_dns_queries(pcap_file)

    assert len(queries) == 2
    assert all(isinstance(q, DNSQuery) for q in queries)
    assert [q.query_name for q in queries] == ["example.com", "other.com"]


def test_extract_tcp_conversations_called_process_error(
    parser: PcapParser, pcap_file: Path, monkeypatch
) -> None:
    """Line 436: a tshark CalledProcessError becomes a RuntimeError carrying stderr."""

    def mock_run(*args, **kwargs):
        raise subprocess.CalledProcessError(
            returncode=2, cmd=["tshark"], stderr="conv,tcp boom"
        )

    monkeypatch.setattr(subprocess, "run", mock_run)

    with pytest.raises(RuntimeError, match="tshark failed: conv,tcp boom"):
        parser.extract_tcp_conversations(pcap_file)
