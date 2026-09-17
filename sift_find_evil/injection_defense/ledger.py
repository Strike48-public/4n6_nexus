"""Tamper-evident injection ledger for the scored / hardening path.

Injection attempts are recorded in the audit hash chain on the MCP server path
(``AuditLogger.log_action("prompt_injection_attempt", ...)``). The scored /
hardening path - which produces the signed, court-facing report - promotes an
attempt to a Finding but keeps no dedicated, append-only, tamper-evident ledger
of attempts. This module builds that ledger from the injection findings already
in a report so an add / drop / reorder of the recorded attempts is detectable.

The ledger is a genesis-anchored SHA-256 hash chain, mirroring
``sift_find_evil.audit`` (each entry's ``prev_hash`` links to the previous
entry's ``entry_hash``). It is:

  * counts-only - it carries the sanitizer's indicator COUNTS, never the raw
    hostile payload (the injection-defense contract), and
  * deterministic - the hashed content excludes any wall-clock field, so the
    same finding set always yields a byte-identical ledger (CI-replayable, like
    the receipt/judge-cache chains).

Pure functions; inputs are never mutated.
"""

from __future__ import annotations

import hashlib
from typing import Any

from ..audit.models import compute_entry_hash

# The artifact-source marker every sanitizer-emitted injection finding carries
# (see injection_defense/sanitizer.finding_from_scan). This is the discriminator
# that selects injection findings out of a mixed finding set.
_INJECTION_SOURCE = "injection_defense.sanitizer"

# Genesis anchor for the chain: the SHA-256 of the empty byte string (a true
# cryptographic genesis). Note this differs from the audit chain's zero-sentinel
# (``GENESIS_HASH = "0"*64``); both are valid anchors, but the ledger uses the
# empty-hash form. What IS shared with the audit chain is the per-entry digest
# primitive (``compute_entry_hash``), so the two hashers can never drift.
_GENESIS = hashlib.sha256(b"").hexdigest()


def _finding_sources(finding: Any) -> list:
    """Return a finding's artifact_sources, whether it is an object or a dict."""
    if isinstance(finding, dict):
        return finding.get("artifact_sources") or []
    return getattr(finding, "artifact_sources", None) or []


def _finding_evidence(finding: Any) -> dict:
    """Return a finding's evidence mapping, whether it is an object or a dict."""
    if isinstance(finding, dict):
        ev = finding.get("evidence")
    else:
        ev = getattr(finding, "evidence", None)
    return ev if isinstance(ev, dict) else {}


def _is_injection_finding(finding: Any) -> bool:
    return _INJECTION_SOURCE in _finding_sources(finding)


def _entry_hash(seq: int, indicator_counts: Any, total: int, prev_hash: str) -> str:
    """Hash of one ledger entry's content, chained to ``prev_hash``.

    The hashed content is the sequence, the counts-only indicators, the total,
    and the previous hash - deliberately NO wall-clock field, so the chain is
    deterministic and replayable. Delegates to the audit chain's shared
    ``compute_entry_hash`` (SHA-256 over ``canonical_bytes``) so the ledger's
    digest can never drift from the audit chain's.
    """
    return compute_entry_hash(
        {
            "seq": seq,
            "indicator_counts": indicator_counts,
            "total_indicators": total,
            "prev_hash": prev_hash,
        }
    )


def build_injection_ledger(findings: list) -> list[dict]:
    """Build a tamper-evident, counts-only injection ledger from findings.

    Args:
        findings: The full finding set (Finding objects or their ``to_dict``
            forms). Only sanitizer-emitted injection findings are recorded;
            inputs are never mutated.

    Returns:
        An ordered list of ledger entries, each
        ``{"seq", "indicator_counts", "total_indicators", "prev_hash",
        "entry_hash"}``, forming a genesis-anchored SHA-256 hash chain. Empty
        when the set contains no injection findings.
    """
    ledger: list[dict] = []
    prev_hash = _GENESIS
    seq = 0
    for finding in findings:
        if not _is_injection_finding(finding):
            continue
        evidence = _finding_evidence(finding)
        indicator_counts = evidence.get("indicator_counts", [])
        total = int(evidence.get("total_indicators", 0))
        entry_hash = _entry_hash(seq, indicator_counts, total, prev_hash)
        ledger.append(
            {
                "seq": seq,
                "indicator_counts": indicator_counts,
                "total_indicators": total,
                "prev_hash": prev_hash,
                "entry_hash": entry_hash,
            }
        )
        prev_hash = entry_hash
        seq += 1
    return ledger


def verify_injection_ledger(ledger: list) -> tuple[bool, str]:
    """Verify a ledger's hash chain (genesis anchor, links, per-entry hashes).

    Args:
        ledger: A ledger produced by :func:`build_injection_ledger`.

    Returns:
        ``(True, message)`` if intact, else ``(False, reason)``. Detects an
        edited entry (recomputed hash mismatch), a dropped entry (broken link or
        sequence gap), and a reorder (broken link).
    """
    if not isinstance(ledger, list):
        return (False, "ledger is not a list")
    prev_hash = _GENESIS
    for index, entry in enumerate(ledger):
        if not isinstance(entry, dict):
            return (False, f"entry {index} is not an object")
        if entry.get("seq") != index:
            return (False, f"entry {index}: sequence gap (an entry was dropped)")
        if entry.get("prev_hash") != prev_hash:
            return (
                False,
                f"entry {index}: prev_hash does not link to the previous entry "
                "(dropped or reordered)",
            )
        recomputed = _entry_hash(
            index,
            entry.get("indicator_counts", []),
            int(entry.get("total_indicators", 0)),
            prev_hash,
        )
        if recomputed != entry.get("entry_hash"):
            return (False, f"entry {index}: entry_hash mismatch (tampered content)")
        prev_hash = recomputed
    return (True, f"OK: {len(ledger)} injection-ledger entr(ies) verified")
