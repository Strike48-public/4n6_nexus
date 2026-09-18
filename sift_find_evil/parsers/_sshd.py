"""Shared sshd authentication-message grammar.

The sshd ``Failed``/``Accepted`` message body is identical whether it is read
from a syslog auth.log line (``parsers.linux_auth``) or from a captured journal
record's ``MESSAGE`` field (``parsers.linux_journald``). Centralising the body
pattern here keeps the two surfaces from drifting: they share *what* an sshd
auth event looks like and differ only in the framing around it (a syslog line
prefix vs. a journal field). See the shared-indicator lesson -- the value
fragment is single-source so variants cannot disagree on the grammar.
"""

from __future__ import annotations

import re
from typing import Optional

# The message body of an sshd auth line, from the event keyword onward:
#   Failed password for root from 203.0.113.5 port 40000 ssh2
#   Accepted publickey for deploy from 10.0.0.5 port 50000 ssh2
#   Failed password for invalid user admin from 198.51.100.9 port 40000 ssh2
# The optional "invalid user " prefix precedes the username on failed attempts.
# IPv4 dotted-quad or an IPv6 literal are both accepted for the source address.
SSHD_AUTH_BODY = (
    r"(?P<event>Failed|Accepted)\s+\S+\s+for\s+"
    r"(?:invalid user\s+)?(?P<user>\S+)\s+"
    r"from\s+(?P<source_ip>\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]+)\s+"
    r"port\s+(?P<port>\d+)"
)

# Anchored at the start of a bare journal MESSAGE value (no syslog prefix).
_SSHD_MESSAGE = re.compile(r"^\s*" + SSHD_AUTH_BODY)


def parse_sshd_auth_message(message: str) -> Optional[dict]:
    """Parse a bare sshd auth MESSAGE into a normalized event, or None.

    Args:
        message: The ``MESSAGE`` field of a journal record (no syslog prefix).

    Returns:
        ``{"event", "user", "source_ip", "port"}`` with ``event`` lowered to
        ``"failed"``/``"accepted"``, or None when the message is not an sshd
        ``Failed``/``Accepted`` password/publickey line.
    """
    match = _SSHD_MESSAGE.match(message)
    if match is None:
        return None
    return {
        "event": match.group("event").lower(),
        "user": match.group("user"),
        "source_ip": match.group("source_ip"),
        "port": match.group("port"),
    }
