"""Coverage-focused tests for MemoryDetector branch/guard paths.

These tests drive the remaining uncovered branches in
``sift_find_evil/detectors/memory_detector.py``: basename normalization
edge cases (forward-slash paths), the unowned-socket-with-no-routable-peer
short-circuit, the Low-confidence (non-canonical-port) lateral-movement
and exfil branches for both Windows and Linux, empty-Linux-process-name
skip, and the IP-helper ValueError / non-IPv4 guards.

As with the sibling suite, the detector consumes pre-parsed Volatility
rows — Volatility is never invoked.
"""

from __future__ import annotations

from sift_find_evil.detectors import memory_detector as md
from sift_find_evil.detectors.memory_detector import MemoryDetector
from sift_find_evil.findings import FindingCategory
from sift_find_evil.memory.volatility_runner import (
    CommandLineRow,
    LinuxNetworkRow,
    LinuxProcessRow,
    NetworkRow,
)


# -- fixture helpers -------------------------------------------------------


def _cmdline_row(pid: int, process: str, args: str) -> CommandLineRow:
    return CommandLineRow(pid=pid, process=process, args=args, raw_row={})


def _netscan_row(
    *,
    pid: int | None = 1234,
    owner: str | None = "powershell.exe",
    protocol: str = "TCPv4",
    local_addr: str | None = "10.0.0.5",
    local_port: int | None = 49152,
    foreign_addr: str | None = "192.168.1.50",
    foreign_port: int | None = 8080,
    state: str | None = "ESTABLISHED",
) -> NetworkRow:
    return NetworkRow(
        pid=pid,
        owner=owner,
        protocol=protocol,
        local_addr=local_addr,
        local_port=local_port,
        foreign_addr=foreign_addr,
        foreign_port=foreign_port,
        state=state,
        raw_row={},
    )


def _linux_proc(
    pid: int, name: str, *, ppid: int = 2, euid: int | None = 0
) -> LinuxProcessRow:
    return LinuxProcessRow(
        pid=pid,
        ppid=ppid,
        name=name,
        euid=euid,
        create_time="2024-01-01T00:00:00",
        raw_row={},
    )


def _linux_net_row(
    *,
    pid: int | None = 4321,
    process: str | None = "bash",
    protocol: str | None = "TCP",
    local_addr: str | None = "10.0.0.9",
    local_port: int | None = 40000,
    foreign_addr: str | None = "192.168.1.77",
    foreign_port: int | None = 8080,
    state: str | None = "ESTABLISHED",
) -> LinuxNetworkRow:
    return LinuxNetworkRow(
        pid=pid,
        process=process,
        protocol=protocol,
        local_addr=local_addr,
        local_port=local_port,
        foreign_addr=foreign_addr,
        foreign_port=foreign_port,
        state=state,
        raw_row={},
    )


# -- cmdline basename forward-slash normalization (line 415) ---------------


def test_cmdline_forward_slash_path_normalizes_to_lolbas() -> None:
    """A Unix-style path to a LOLBAS launcher still resolves the basename."""
    row = _cmdline_row(10, "/usr/bin/powershell.exe", "-NoProfile -Enc AAAA")
    findings = MemoryDetector().analyze(cmdline=[row])
    cmd_findings = [f for f in findings if f.category == FindingCategory.PERSISTENCE]
    assert cmd_findings, "forward-slash path should still match LOLBAS basename"
    reasons = cmd_findings[0].evidence["reasons"]
    assert any("powershell.exe" in r for r in reasons)


# -- unowned socket with no routable peer short-circuits (line 534) --------


def test_unowned_socket_loopback_peer_returns_none() -> None:
    """pid=None + no owner but loopback foreign addr is not a finding."""
    row = _netscan_row(
        pid=None, owner=None, foreign_addr="127.0.0.1", foreign_port=8080
    )
    assert MemoryDetector().analyze(netscan=[row]) == []


def test_unowned_socket_missing_foreign_addr_returns_none() -> None:
    """pid=None + no owner + empty foreign addr is not a finding."""
    row = _netscan_row(pid=None, owner="   ", foreign_addr=None)
    assert MemoryDetector().analyze(netscan=[row]) == []


# -- Windows lateral movement Low-confidence branch (line 636) -------------


def test_lateral_movement_non_canonical_port_is_low_confidence() -> None:
    """RFC1918 peer on a non-SMB/WinRM/RPC port stays Low/medium."""
    row = _netscan_row(foreign_addr="192.168.1.50", foreign_port=8080)
    findings = MemoryDetector().analyze(netscan=[row])
    lm = [f for f in findings if f.category == FindingCategory.LATERAL_MOVEMENT]
    assert len(lm) == 1
    assert lm[0].confidence_label == "Low"
    assert lm[0].severity == "medium"


# -- linux pslist empty name skip (line 820) -------------------------------


def test_linux_pslist_empty_name_skipped() -> None:
    """A whitespace-only COMM produces no finding."""
    rows = [_linux_proc(100, "   "), _linux_proc(101, "")]
    assert MemoryDetector().analyze(linux_pslist=rows) == []


# -- linux lateral movement Low-confidence branch (line 963) ---------------


def test_linux_lateral_movement_non_canonical_port_is_low_confidence() -> None:
    """Shell to RFC1918 peer on a non-LM port stays Low/medium."""
    row = _linux_net_row(process="bash", foreign_addr="192.168.1.77", foreign_port=8080)
    findings = MemoryDetector().analyze(linux_sockstat=[row])
    lm = [f for f in findings if f.category == FindingCategory.LATERAL_MOVEMENT]
    assert len(lm) == 1
    assert lm[0].confidence_label == "Low"
    assert lm[0].severity == "medium"


# -- linux exfil Low-confidence branch (line 1020) -------------------------


def test_linux_exfil_non_reverse_shell_port_is_low_confidence() -> None:
    """Shell to public peer on a non-reverse-shell port stays Low/medium."""
    row = _linux_net_row(process="python3", foreign_addr="8.8.8.8", foreign_port=443)
    findings = MemoryDetector().analyze(linux_sockstat=[row])
    exfil = [f for f in findings if f.category == FindingCategory.DATA_EXFILTRATION]
    assert len(exfil) == 1
    assert exfil[0].confidence_label == "Low"
    assert exfil[0].severity == "medium"


# -- _normalize_basename branches (lines 1068, 1070) -----------------------


def test_normalize_basename_backslash_path() -> None:
    assert md._normalize_basename("C:\\Windows\\System32\\cmd.exe") == "cmd.exe"


def test_normalize_basename_forward_slash_path() -> None:
    assert md._normalize_basename("/usr/local/bin/python3") == "python3"


def test_normalize_basename_bare_name_unchanged() -> None:
    assert md._normalize_basename("Bash") == "bash"


# -- _is_rfc1918 guards (lines 1090, 1091, 1097) ---------------------------


def test_is_rfc1918_invalid_address_returns_false() -> None:
    assert md._is_rfc1918("not-an-ip") is False


def test_is_rfc1918_ipv6_returns_false() -> None:
    """A non-IPv4 (IPv6) address is not treated as RFC1918 here."""
    assert md._is_rfc1918("fc00::1") is False


def test_is_rfc1918_private_ipv4_true() -> None:
    assert md._is_rfc1918("10.1.2.3") is True


def test_is_rfc1918_public_ipv4_false() -> None:
    assert md._is_rfc1918("8.8.8.8") is False


# -- _is_loopback guard (lines 1104, 1105) ---------------------------------


def test_is_loopback_invalid_address_returns_false() -> None:
    assert md._is_loopback("garbage") is False


def test_is_loopback_valid_loopback_true() -> None:
    assert md._is_loopback("127.0.0.1") is True


# -- _is_ipv6 guard (lines 1111, 1112) -------------------------------------


def test_is_ipv6_invalid_address_returns_false() -> None:
    assert md._is_ipv6("nonsense") is False


def test_is_ipv6_valid_v6_true() -> None:
    assert md._is_ipv6("::1") is True


def test_is_ipv6_v4_false() -> None:
    assert md._is_ipv6("10.0.0.1") is False
