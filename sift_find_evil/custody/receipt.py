"""Cryptographic finding receipts (gallery idea #4).

Each finding is bound to a signed envelope that carries:

  * ``finding_hash``  - SHA-256 over the finding's canonical content (identity)
  * ``image_sha256``  - the evidence image the run was performed against
  * ``tool``/``tool_version`` - the provenance that produced the finding
  * ``signature``     - HMAC-SHA256 over all of the above under a per-run key

Only code holding the per-run key can mint a receipt, so a hallucinated finding
(one the engine never produced through the tool boundary) has no valid receipt,
and any post-hoc edit to the finding body, the bound image hash, or the
provenance breaks verification. This mirrors the canonical-JSON + HMAC
convention already proven in ``sift_find_evil/approval/manager.py``.

Independently built by: OATH MCP, Stigmergy, VERDICT, ClaimGuard, Agentropix
MCP, logflip-sift-agent.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from typing import Optional

# HMAC keys shorter than this are cryptographically meaningless for our purpose;
# refuse to mint rather than issue a forgeable receipt (mirrors approval/).
_MIN_KEY_BYTES = 32


def _canonical(payload: dict) -> bytes:
    """Serialize to reproducible canonical UTF-8 JSON bytes."""
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), default=str
    ).encode("utf-8")


def _finding_hash(finding: dict) -> str:
    """SHA-256 over the finding's canonical content - its stable identity."""
    return hashlib.sha256(_canonical(finding)).hexdigest()


def _receipt_message(
    finding_hash: str,
    image_sha256: str,
    tool: str,
    tool_version: Optional[str],
) -> bytes:
    """The exact bytes the signature is computed over.

    Every field that defines the receipt is bound: the finding identity, the
    evidence image, and the tool provenance. Editing any of them, or copying a
    signature onto a different finding, changes this message and fails
    verification.
    """
    return _canonical(
        {
            "finding_hash": finding_hash,
            "image_sha256": image_sha256,
            "tool": tool,
            "tool_version": tool_version,
        }
    )


def mint_receipt(
    finding: dict,
    key: bytes,
    image_sha256: str,
    tool: str,
    tool_version: Optional[str] = None,
) -> dict:
    """Mint a signed receipt binding ``finding`` to the evidence + provenance.

    Args:
        finding: The finding content (any JSON-serializable dict).
        key: Per-run HMAC key; must be at least 32 bytes.
        image_sha256: SHA-256 of the evidence image this run analyzed.
        tool: Name of the forensic tool that produced the finding.
        tool_version: Optional tool version string.

    Returns:
        A receipt dict: ``{finding_hash, image_sha256, tool, tool_version,
        signature}``.

    Raises:
        ValueError: if the key is shorter than 32 bytes.
    """
    if len(key) < _MIN_KEY_BYTES:
        raise ValueError(
            f"receipt key must be at least {_MIN_KEY_BYTES} bytes; got {len(key)}"
        )
    fh = _finding_hash(finding)
    signature = hmac.new(
        key, _receipt_message(fh, image_sha256, tool, tool_version), hashlib.sha256
    ).hexdigest()
    return {
        "finding_hash": fh,
        "image_sha256": image_sha256,
        "tool": tool,
        "tool_version": tool_version,
        "signature": signature,
    }


def verify_receipt(finding: dict, receipt: dict, key: bytes) -> bool:
    """Return True iff ``receipt`` is a valid seal over ``finding`` under ``key``.

    Recomputes the finding hash from the presented finding and the HMAC over the
    receipt's bound fields, comparing in constant time. Returns False (never
    raises) on tampered content, a rebound image hash, a copied signature, a
    wrong key, or a malformed signature string.
    """
    try:
        if len(key) < _MIN_KEY_BYTES:
            return False
        stored_sig = receipt.get("signature")
        if not isinstance(stored_sig, str) or len(stored_sig) != 64:
            return False
        if not all(c in "0123456789abcdef" for c in stored_sig):
            return False

        # The finding presented now must hash to the receipt's bound identity.
        if _finding_hash(finding) != receipt.get("finding_hash"):
            return False

        expected = hmac.new(
            key,
            _receipt_message(
                receipt["finding_hash"],
                receipt.get("image_sha256"),
                receipt.get("tool"),
                receipt.get("tool_version"),
            ),
            hashlib.sha256,
        ).hexdigest()
        return hmac.compare_digest(expected, stored_sig)
    except (KeyError, TypeError):
        return False


class ReceiptMinter:
    """Run-scoped receipt factory bound to one key and one evidence image.

    Holds the per-run HMAC key and the evidence-image SHA-256 so callers at the
    MCP output chokepoint mint receipts without re-passing them each time.
    """

    def __init__(self, key: bytes, image_sha256: str):
        if len(key) < _MIN_KEY_BYTES:
            raise ValueError(
                f"receipt key must be at least {_MIN_KEY_BYTES} bytes; got {len(key)}"
            )
        self._key = key
        self.image_sha256 = image_sha256

    def mint(
        self, finding: dict, tool: str, tool_version: Optional[str] = None
    ) -> dict:
        """Mint a receipt for ``finding`` bound to this run's key and image."""
        return mint_receipt(
            finding,
            key=self._key,
            image_sha256=self.image_sha256,
            tool=tool,
            tool_version=tool_version,
        )

    def verify(self, finding: dict, receipt: dict) -> bool:
        """Verify a receipt against this run's key."""
        return verify_receipt(finding, receipt, key=self._key)
