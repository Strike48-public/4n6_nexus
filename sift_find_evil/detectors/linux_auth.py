"""Linux authentication detector (SFE-rfhz).

The engine's credential detectors are Windows/memory-centric. This module fills
the Linux gap by inspecting normalized SSH authentication events (from
``parsers.linux_auth.parse_auth_events``) for a **brute-force compromise**: a
single ``(source IP, account)`` pair that accumulates at least
:data:`_FAILED_THRESHOLD` ``Failed password`` attempts which are *then* followed
by an ``Accepted`` login for that same account.

That pairing is the high-signal shape -- password guessing against one account
(MITRE ATT&CK **T1110.001**) that culminates in a valid-account login
(**T1078**). Three deliberate precision guards keep it honest:

- **Per-account grouping.** Failures and the success must belong to the same
  ``(ip, user)`` pair. Grouping by IP alone would false-positive in NAT /
  shared-egress environments, where one user's typos plus a *different* user's
  legitimate login share a source IP.
- **Temporal ordering.** Only failures that occur *before* the account's first
  accepted login count. A successful login followed later by password typos is
  not a compromise, so it does not fire.
- **Success required.** A failed flood that never succeeds is a mere attempt
  (no compromise). Detecting an attempt without success is intentionally left
  to a future, lower-severity signal so this finding always marks a breach.

The detector is stateless and never mutates the artifacts dict it is given.
"""

from __future__ import annotations

from typing import Any, Iterable

from ..findings import Finding, FindingCategory

# Failed attempts from one source IP before an accepted login is treated as a
# brute-force success. Five tolerates ordinary password typos while a real
# guessing run produces far more.
_FAILED_THRESHOLD = 5


def brute_forced_pairs(events: Iterable[dict[str, Any]]) -> dict[tuple[str, str], int]:
    """Return the ``(ip, user)`` pairs the auth surface treats as compromised.

    A pair qualifies when it accumulates at least :data:`_FAILED_THRESHOLD`
    failed attempts *before* its first accepted login and has an accepted login
    (see the module docstring for the precision rationale). Events are assumed
    chronological (the parser preserves log order).

    This is the single source of truth for "which ``(ip, user)`` the auth
    surface owns as a brute-force compromise". :class:`LinuxAuthDetector` builds
    one finding per returned pair, and the wtmp login-session detector
    (``LinuxLoginSessionDetector``) reuses it to dedupe against this surface so
    the same compromise is not reported twice under ``CREDENTIAL_ACCESS``.

    Args:
        events: Normalized SSH auth events (see
            :func:`~sift_find_evil.parsers.linux_auth.parse_auth_events`).

    Returns:
        ``{(ip, user): pre_success_failure_count}`` in first-appearance order
        (dict insertion order), one entry per compromised pair.
    """
    pre_success_failures: dict[tuple[str, str], int] = {}
    has_success: dict[tuple[str, str], bool] = {}
    pair_order: list[tuple[str, str]] = []
    for event in events:
        ip = str(event.get("source_ip") or "")
        if not ip:
            continue
        key = (ip, str(event.get("user") or "?"))
        if key not in pre_success_failures:
            pre_success_failures[key] = 0
            has_success[key] = False
            pair_order.append(key)
        kind = event.get("event")
        if kind == "accepted":
            has_success[key] = True
        elif kind == "failed" and not has_success[key]:
            pre_success_failures[key] += 1

    return {
        key: pre_success_failures[key]
        for key in pair_order
        if pre_success_failures[key] >= _FAILED_THRESHOLD and has_success[key]
    }


class LinuxAuthDetector:
    """Detects SSH brute-force compromises from parsed auth-log events.

    The detector is stateless; :meth:`analyze` is a pure function of its input
    and never mutates the artifacts dict it is given.
    """

    def analyze(self, artifacts: dict[str, Any]) -> list[Finding]:
        """Scan auth events and return brute-force-compromise findings.

        Args:
            artifacts: Mapping that may contain ``auth_events`` -- a list of
                normalized SSH auth events (see
                :func:`~sift_find_evil.parsers.linux_auth.parse_auth_events`).
                A missing key is treated as an empty list.

        Returns:
            One :class:`Finding` per ``(source IP, account)`` pair whose
            pre-success failure count reaches :data:`_FAILED_THRESHOLD` and which
            has an accepted login, tagged
            :attr:`FindingCategory.CREDENTIAL_ACCESS`. Events are assumed to be
            in chronological order (the parser preserves log order). Ordered by
            first appearance of each offending pair.
        """
        events = artifacts.get("auth_events") or []
        pairs = brute_forced_pairs(events)
        sources = _pair_sources(events, set(pairs))
        return [
            self._build_finding(ip, user, failures, sources[(ip, user)])
            for (ip, user), failures in pairs.items()
        ]

    @staticmethod
    def _build_finding(
        ip: str, user: str, failures: int, artifact_sources: list[str]
    ) -> Finding:
        """Build the brute-force-compromise finding for one (ip, user) pair."""
        return Finding(
            title=f"SSH brute-force compromise of {user} from {ip}",
            description=(
                f"Source {ip} made {failures} failed SSH password attempts "
                f"against '{user}' and then successfully authenticated as that "
                "account. Password guessing that culminated in a valid-account "
                "login."
            ),
            finding_type="behavior",
            severity="critical",
            category=FindingCategory.CREDENTIAL_ACCESS,
            evidence={
                "source_ip": ip,
                "compromised_user": user,
                "failed_attempts": failures,
                "reason": "failed-attempt flood followed by an accepted login",
                "mitre_technique": "T1110.001",
            },
            reasoning_chain=[
                f"{failures} failed SSH attempts against '{user}' came from {ip} "
                "before any success.",
                f"The same IP then authenticated successfully as '{user}'.",
                "Brute-force guessing culminating in a valid-account login "
                "(T1110.001 -> T1078).",
            ],
            artifact_sources=artifact_sources,
        )


def _pair_sources(
    events: Iterable[dict[str, Any]], pairs: set[tuple[str, str]]
) -> dict[tuple[str, str], list[str]]:
    """Collect the artifact surfaces that contributed each compromised pair.

    A pair's events may come from the syslog auth.log surface, a captured
    journald dump, or both (see the collector's cross-surface merge), so the
    finding cites the true source(s) rather than always claiming ``auth_log``.
    Events carry an optional ``source`` key; a missing key defaults to
    ``"auth_log"`` (the auth.log parser does not stamp one). Sources are ordered
    auth_log-first for a stable, deterministic finding.
    """
    _ORDER = {"auth_log": 0, "journald": 1}
    found: dict[tuple[str, str], set[str]] = {pair: set() for pair in pairs}
    for event in events:
        ip = str(event.get("source_ip") or "")
        key = (ip, str(event.get("user") or "?"))
        if key in found:
            found[key].add(str(event.get("source") or "auth_log"))
    return {
        pair: sorted(surfaces, key=lambda s: (_ORDER.get(s, 99), s))
        for pair, surfaces in found.items()
    }
