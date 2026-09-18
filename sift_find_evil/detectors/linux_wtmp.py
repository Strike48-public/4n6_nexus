"""Linux login-session detector (SFE-fjla).

Complements the auth.log brute-force detector (``LinuxAuthDetector``,
T1110.001) with a *valid-accounts* signal recovered from the binary login
record (wtmp/utmp, parsed by
:func:`~sift_find_evil.parsers.linux_wtmp.parse_login_sessions`): an
**interactive privileged login from an external address** -- MITRE ATT&CK
**T1078** (Valid Accounts). A recorded ``root`` session sourced from a routable
off-box IP is a high-signal indicator of account abuse regardless of *how* the
credential was obtained, so it catches compromises that never showed a
brute-force pattern in auth.log (stolen key, password reuse, rotated-away log).

Two precision guards keep it honest:

- **Privileged account only.** A normal-user login from outside is routine; a
  ``root`` login is not (interactive root SSH is widely disabled). Only the
  privileged set fires.
- **External source only.** A local/console login (no address) or a login from
  an RFC1918 / loopback / link-local address is in-perimeter and does not fire.

**Dedupe vs auth.log.** Both surfaces emit ``CREDENTIAL_ACCESS``. A ``(ip,
user)`` pair the auth surface already owns as a brute-force compromise (see
:func:`~sift_find_evil.detectors.linux_auth.brute_forced_pairs`) is suppressed
here so one compromise is not double-counted.

The detector is stateless and never mutates the artifacts dict it is given.
"""

from __future__ import annotations

import ipaddress
from typing import Any

from ..findings import Finding, FindingCategory
from .linux_auth import brute_forced_pairs

# Accounts whose interactive login from outside the perimeter is high-signal.
# root is the canonical privileged account; interactive root SSH is normally
# disabled, so a recorded root session from an external IP warrants a finding.
_PRIVILEGED_USERS: frozenset[str] = frozenset({"root"})


def _is_external_ip(value: str) -> bool:
    """Return True when ``value`` is a routable, off-perimeter IP address.

    Excludes loopback, RFC1918 private, link-local, unspecified, multicast and
    reserved ranges. NOTE (matches the RFC-5737 caveat elsewhere in the engine):
    Python's :pyattr:`ipaddress.is_private`/``is_reserved`` also classify the
    documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) as
    non-global, so a fixture must plant a *genuine* public IP (not a doc range)
    or this returns False and the finding never fires (vacuous pass).
    """
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return not (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_unspecified
        or ip.is_multicast
        or ip.is_reserved
    )


class LinuxLoginSessionDetector:
    """Detects privileged external logins from parsed wtmp/utmp sessions.

    The detector is stateless; :meth:`analyze` is a pure function of its input
    and never mutates the artifacts dict it is given.
    """

    def analyze(self, artifacts: dict[str, Any]) -> list[Finding]:
        """Scan login sessions and return valid-account-abuse findings.

        Args:
            artifacts: Mapping that may contain ``login_sessions`` (see
                :func:`~sift_find_evil.parsers.linux_wtmp.parse_login_sessions`)
                and, for dedupe, ``auth_events``. Missing keys are empty.

        Returns:
            One :class:`Finding` per ``(external IP, privileged user)`` login,
            tagged :attr:`FindingCategory.CREDENTIAL_ACCESS`, in first-appearance
            order. Pairs already reported as a brute-force compromise by the
            auth surface are suppressed.
        """
        sessions = artifacts.get("login_sessions") or []
        auth_owned = set(brute_forced_pairs(artifacts.get("auth_events") or []))

        first_session: dict[tuple[str, str], dict[str, Any]] = {}
        pair_order: list[tuple[str, str]] = []
        for session in sessions:
            user = str(session.get("user") or "")
            ip = str(session.get("source_ip") or "")
            if user not in _PRIVILEGED_USERS or not _is_external_ip(ip):
                continue
            key = (ip, user)
            if key in auth_owned or key in first_session:
                continue
            first_session[key] = session
            pair_order.append(key)

        return [self._build_finding(first_session[key]) for key in pair_order]

    @staticmethod
    def _build_finding(session: dict[str, Any]) -> Finding:
        """Build the valid-account login finding for one privileged session."""
        user = str(session.get("user") or "?")
        ip = str(session.get("source_ip") or "?")
        line = str(session.get("line") or "?")
        # The session comes from the wtmp binary or a captured journald dump
        # (collector merge); name the true surface in the prose and citation so
        # a journald-sourced finding does not falsely claim a wtmp record.
        source = str(session.get("source") or "wtmp")
        record_label = "the journal" if source == "journald" else "wtmp/utmp"
        return Finding(
            title=f"Privileged external login: {user} from {ip}",
            description=(
                f"{record_label} records an interactive '{user}' login on "
                f"'{line}' sourced from external address {ip}. A privileged "
                "account logging in from off-perimeter is valid-account abuse "
                "(T1078)."
            ),
            finding_type="behavior",
            severity="high",
            category=FindingCategory.CREDENTIAL_ACCESS,
            evidence={
                "source_ip": ip,
                "account": user,
                "line": line,
                "host": str(session.get("host") or ""),
                "timestamp": session.get("timestamp"),
                "reason": "interactive privileged login from an external address",
                "mitre_technique": "T1078",
            },
            reasoning_chain=[
                f"{record_label} records an interactive '{user}' session on "
                f"'{line}'.",
                f"The session is sourced from external address {ip}.",
                "A privileged account logging in from off-perimeter is "
                "valid-account abuse (T1078).",
            ],
            artifact_sources=[source],
        )
