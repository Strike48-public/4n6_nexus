"""Canonical JSON serialization - the single source of truth.

One reproducible byte encoding used everywhere a hash or signature is computed
over structured data: the audit hash chain, HMAC finding receipts, Ed25519
receipts, and approval signatures. Consolidated here (PR #3 review) so the form
is defined once - a future change to canonicalization can never drift between
the producers and the standalone offline verifier.

The rule: ``sort_keys=True`` (dict key order is normalized; list order is
preserved), tight separators (no incidental whitespace), and ``default=str`` so
non-JSON-native values (e.g. datetimes) coerce deterministically instead of
raising.

NOTE: ``tools/verify_chain.py`` deliberately re-implements this from the stdlib
rather than importing it - that independence is what lets it detect writer/reader
drift (gallery idea #5). Keep the two in lockstep by hand.
"""

from __future__ import annotations

import json
from typing import Any


def canonical_json(payload: Any) -> str:
    """Return the canonical JSON string for ``payload`` (sorted keys, no spaces)."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


def canonical_bytes(payload: Any) -> bytes:
    """Return the canonical JSON encoding as UTF-8 bytes (for hashing/signing)."""
    return canonical_json(payload).encode("utf-8")
