"""Linux wtmp/utmp binary login-session parser (SFE-fjla).

``/var/log/wtmp`` (historical logins/logouts) and ``/var/run/utmp`` (currently
active sessions) are fixed-record binary logs of C ``struct utmp`` entries --
the canonical dead-disk record of *who logged in, from where, and when*. This
parser binary-decodes them off a mounted image root and returns the interactive
login sessions (``USER_PROCESS`` records) as normalized event dicts for
``LinuxLoginSessionDetector``.

The bytes are attacker-controlled evidence, so the read goes through
:func:`~sift_find_evil.parsers._linux_fs.read_bytes_contained` (symlink-escape
containment + size cap) and record decoding is defensive: a truncated tail or a
record that fails to unpack is skipped, never fatal.

**Record layout** (glibc ``struct utmp``, x86-64, 384 bytes)::

    short ut_type; (2)  + 2 pad   int ut_pid; (4)
    char  ut_line[32];  char ut_id[4];  char ut_user[32];  char ut_host[256];
    short e_termination; short e_exit;  int ut_session;
    int   tv_sec; int tv_usec;  int ut_addr_v6[4];  char __unused[20]

``ut_addr_v6`` holds the remote address in network byte order; for an IPv4
login only ``ut_addr_v6[0]`` is set. Local/console logins carry a zero address.
"""

from __future__ import annotations

import ipaddress
import struct
from pathlib import Path
from typing import Any

from ._linux_fs import read_bytes_contained

# glibc struct utmp, x86-64: little-endian, explicit padding, 384 bytes/record.
_RECORD_FMT = "<hxxi32s4s32s256shhiii4i20s"
_RECORD_SIZE = struct.calcsize(_RECORD_FMT)  # 384

# ut_type for an interactive user login session.
_USER_PROCESS = 7

# Login-record sources on a mounted root, relative to the image root.
_LOGIN_SOURCES: tuple[str, ...] = (
    "var/log/wtmp",
    "var/run/utmp",
    "run/utmp",
)


def _cstr(raw: bytes) -> str:
    """Decode a NUL-terminated fixed-width C string field."""
    return raw.split(b"\0", 1)[0].decode("utf-8", errors="replace")


def _decode_addr(a0: int, a1: int, a2: int, a3: int, host: str) -> str:
    """Resolve the remote address from ut_addr_v6, falling back to ut_host.

    ``ut_addr_v6`` is stored in network byte order; unpacked here as
    little-endian ints, re-packing each word little-endian reproduces the
    original network-order bytes. An all-zero address means a local/console
    login, in which case ``ut_host`` is used only when it is an IP literal
    (it is often a tty name or the kernel version for pseudo-records).
    """
    if a0 or a1 or a2 or a3:
        if not (a1 or a2 or a3):
            return str(ipaddress.IPv4Address(struct.pack("<I", a0 & 0xFFFFFFFF)))
        packed = struct.pack("<IIII", *(w & 0xFFFFFFFF for w in (a0, a1, a2, a3)))
        return str(ipaddress.IPv6Address(packed))
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        return ""


def parse_login_sessions(root: Path) -> list[dict[str, Any]]:
    """Parse interactive login sessions from wtmp/utmp under a mounted root.

    Args:
        root: Mounted image root (or a live-response bundle laid out like a root
            filesystem). Missing sources are skipped, so a partial image still
            parses.

    Returns:
        One dict per ``USER_PROCESS`` login record, in file-then-record order,
        each with keys ``user``, ``line``, ``host``, ``source_ip`` (empty for a
        local/console login), ``timestamp`` (Unix epoch seconds) and
        ``source_path``. Non-login record types, records with no user, and any
        malformed/truncated tail bytes are dropped.
    """
    sessions: list[dict[str, Any]] = []
    for rel in _LOGIN_SOURCES:
        data = read_bytes_contained(root / rel, root)
        if not data:
            continue
        for offset in range(0, len(data) - _RECORD_SIZE + 1, _RECORD_SIZE):
            record = data[offset : offset + _RECORD_SIZE]
            try:
                fields = struct.unpack(_RECORD_FMT, record)
            except struct.error:
                continue
            ut_type, _pid, line, _id, user, host = fields[:6]
            tv_sec = fields[9]
            addr = fields[11:15]
            if ut_type != _USER_PROCESS:
                continue
            user_str = _cstr(user)
            if not user_str:
                continue
            host_str = _cstr(host)
            sessions.append(
                {
                    "user": user_str,
                    "line": _cstr(line),
                    "host": host_str,
                    "source_ip": _decode_addr(*addr, host_str),
                    "timestamp": tv_sec,
                    "source_path": f"/{rel}",
                }
            )
    return sessions
