"""Tests for the Linux wtmp/utmp binary login-session parser (SFE-fjla).

Exercises binary decoding of glibc ``struct utmp`` records off a mounted image
root: USER_PROCESS extraction, non-login record filtering, IPv4 address
decoding from ``ut_addr_v6``, local/console (no-address) sessions, and
robustness to a truncated tail. Fixtures are synthetic in-memory byte blobs
written under a tmp root, so no real login data is touched.
"""

from __future__ import annotations

import ipaddress
import struct
from pathlib import Path

from sift_find_evil.parsers.linux_wtmp import parse_login_sessions

_FMT = "<hxxi32s4s32s256shhiii4i20s"
_USER_PROCESS = 7
_BOOT_TIME = 2


def _addr_words(ip: str) -> tuple[int, int, int, int]:
    if not ip:
        return (0, 0, 0, 0)
    packed = ipaddress.IPv4Address(ip).packed
    return (struct.unpack("<I", packed)[0], 0, 0, 0)


def _record(ut_type: int, user: str, line: str, host: str, ip: str, sec: int) -> bytes:
    a0, a1, a2, a3 = _addr_words(ip)
    return struct.pack(
        _FMT,
        ut_type,
        1000,
        line.encode()[:31].ljust(32, b"\0"),
        b"ts01",
        user.encode()[:31].ljust(32, b"\0"),
        host.encode()[:255].ljust(256, b"\0"),
        0,
        0,
        0,
        sec,
        0,
        a0,
        a1,
        a2,
        a3,
        b"\0" * 20,
    )


def _write_wtmp(tmp_path: Path, blob: bytes) -> Path:
    root = tmp_path / "root"
    (root / "var" / "log").mkdir(parents=True)
    (root / "var" / "log" / "wtmp").write_bytes(blob)
    return root


def test_record_size_is_384_bytes() -> None:
    """The struct layout matches the glibc on-disk utmp record size."""
    assert struct.calcsize(_FMT) == 384


def test_user_process_login_is_parsed(tmp_path: Path) -> None:
    """A USER_PROCESS record yields a normalized session with decoded IPv4."""
    root = _write_wtmp(
        tmp_path,
        _record(_USER_PROCESS, "root", "pts/2", "", "45.83.122.10", 1710000400),
    )

    sessions = parse_login_sessions(root)

    assert len(sessions) == 1
    s = sessions[0]
    assert s["user"] == "root"
    assert s["line"] == "pts/2"
    assert s["source_ip"] == "45.83.122.10"
    assert s["timestamp"] == 1710000400
    assert s["source_path"] == "/var/log/wtmp"


def test_ipv6_login_address_is_decoded(tmp_path: Path) -> None:
    """A USER_PROCESS record with an IPv6 ut_addr_v6 decodes to the IPv6 str."""
    # ut_addr_v6 is 4 signed int32 fields ("<...4i..."); unpack signed so the
    # high words fit the pack format (the parser masks & 0xFFFFFFFF on read).
    words = struct.unpack("<iiii", ipaddress.IPv6Address("2001:db8::1").packed)
    blob = struct.pack(
        _FMT,
        _USER_PROCESS,
        1000,
        b"pts/3".ljust(32, b"\0"),
        b"ts01",
        b"root".ljust(32, b"\0"),
        b"".ljust(256, b"\0"),
        0,
        0,
        0,
        1710000500,
        0,
        *words,
        b"\0" * 20,
    )
    root = _write_wtmp(tmp_path, blob)

    sessions = parse_login_sessions(root)

    assert len(sessions) == 1
    assert sessions[0]["source_ip"] == "2001:db8::1"


def test_non_login_record_types_are_skipped(tmp_path: Path) -> None:
    """BOOT_TIME (and other non-USER_PROCESS) records are not sessions."""
    root = _write_wtmp(
        tmp_path, _record(_BOOT_TIME, "reboot", "~", "6.8.0-generic", "", 1710000000)
    )

    assert parse_login_sessions(root) == []


def test_local_console_login_has_empty_source_ip(tmp_path: Path) -> None:
    """A login with a zero ut_addr and non-IP host resolves to no source IP."""
    root = _write_wtmp(
        tmp_path, _record(_USER_PROCESS, "root", "tty1", "", "", 1710000100)
    )

    sessions = parse_login_sessions(root)

    assert len(sessions) == 1
    assert sessions[0]["source_ip"] == ""


def test_truncated_tail_is_ignored(tmp_path: Path) -> None:
    """A trailing partial record (not a full 384 bytes) is dropped, not fatal."""
    blob = _record(_USER_PROCESS, "root", "pts/2", "", "45.83.122.10", 1710000400)
    root = _write_wtmp(tmp_path, blob + b"\x01\x02\x03garbage")

    sessions = parse_login_sessions(root)

    assert len(sessions) == 1
    assert sessions[0]["user"] == "root"


def test_missing_wtmp_returns_empty(tmp_path: Path) -> None:
    """A root with no wtmp/utmp yields an empty list, not an error."""
    (tmp_path / "root").mkdir()

    assert parse_login_sessions(tmp_path / "root") == []
