"""Merkle root over a run's finding set + a publicly-verifiable run anchor.

The per-finding receipts (``receipt.py`` HMAC, ``signing.py`` Ed25519) each prove
one finding in isolation. They do NOT prove the *set*: a party who drops or
reorders findings leaves every surviving receipt individually valid. The Merkle
root closes that gap - it folds every finding hash into one value, so adding,
deleting, or reordering any finding changes the root.

The signed *anchor* binds that root to the evidence image and the finding count
under one Ed25519 signature. Verified together with the receipts (see
``tools/verify_receipts.py``), it lets a third party confirm offline that one
keyholder signed exactly this set of findings for this image - and, when that
keyholder's public key is published and supplied as a trust root, that the signer
is the engine (provenance), not an attacker who re-signed a doctored set. The
signer key is pinnable via ``$SFE_RECEIPT_ED25519_KEY``; an unpinned per-run key
proves internal consistency only, not provenance (and a TOTAL wipe of the set
cannot be told from a genuinely clean run without the pinned key - see
``tools/verify_receipts.py`` for the exact boundary). This is the local,
deterministic, CI-safe core of the "transparency anchor" bar; submitting the same
root to an external transparency log (Rekor/Sigstore) is a documented extension
that layers on top without changing this structure.

Tree construction follows RFC 6962 (Certificate Transparency): leaves are
domain-separated with a ``0x00`` prefix and interior nodes with ``0x01`` so a
leaf digest can never be reinterpreted as an interior node (second-preimage
hardening). The empty tree hashes the empty string, per the same RFC.

``cryptography`` is optional (the connector extra); the Merkle functions are pure
stdlib and always available, while the anchor sign/verify helpers lazily reuse
``signing`` and raise a clear error only if actually invoked without it.
"""

from __future__ import annotations

import hashlib

from ..canonical import canonical_bytes
from . import signing

_ANCHOR_ALGORITHM = "ed25519"


def _leaf_hash(finding_hash: str) -> bytes:
    """RFC 6962 leaf hash: SHA-256 over ``0x00 || finding_hash_bytes``."""
    return hashlib.sha256(b"\x00" + bytes.fromhex(finding_hash)).digest()


def _node_hash(left: bytes, right: bytes) -> bytes:
    """RFC 6962 interior node hash: SHA-256 over ``0x01 || left || right``."""
    return hashlib.sha256(b"\x01" + left + right).digest()


def merkle_root(finding_hashes: list[str]) -> str:
    """Return the RFC 6962 Merkle tree hash over ``finding_hashes`` as hex.

    Args:
        finding_hashes: The ordered per-finding SHA-256 hex digests (the
            ``finding_hash`` field each receipt already carries). Order is
            significant - reordering yields a different root.

    Returns:
        The 64-char hex Merkle root. The empty set hashes the empty string
        (RFC 6962), so an empty run still has a well-defined, verifiable root.
    """
    if not finding_hashes:
        return hashlib.sha256(b"").hexdigest()

    level = [_leaf_hash(fh) for fh in finding_hashes]
    while len(level) > 1:
        nxt: list[bytes] = []
        for i in range(0, len(level), 2):
            if i + 1 < len(level):
                nxt.append(_node_hash(level[i], level[i + 1]))
            else:
                # Odd node is promoted unchanged to the next level (RFC 6962
                # duplicates the last leaf's *position*, not its hash).
                nxt.append(level[i])
        level = nxt
    return level[0].hex()


def _anchor_message(
    merkle_root_hex: str, image_sha256: str, finding_count: int
) -> bytes:
    """The exact bytes the anchor signature is computed over.

    Binds the set root, the evidence image, and the finding count so none can be
    altered without invalidating the signature.
    """
    return canonical_bytes(
        {
            "merkle_root": merkle_root_hex,
            "image_sha256": image_sha256,
            "finding_count": finding_count,
        }
    )


def mint_anchor(
    merkle_root_hex: str,
    image_sha256: str,
    finding_count: int,
    private_pem: bytes,
) -> dict:
    """Mint a publicly-verifiable Ed25519 anchor over a run's Merkle root.

    Args:
        merkle_root_hex: The run's :func:`merkle_root` value.
        image_sha256: SHA-256 of the evidence image this run analyzed.
        finding_count: Number of findings folded into the root.
        private_pem: The signer's PEM-encoded Ed25519 private key.

    Returns:
        A self-contained anchor dict: ``{merkle_root, image_sha256,
        finding_count, algorithm, public_key_pem, signature}``. Verification
        needs no secret.

    Raises:
        RuntimeError: if the ``cryptography`` package is not available.
    """
    signing._require_crypto()
    from cryptography.hazmat.primitives import serialization

    private_key = serialization.load_pem_private_key(private_pem, password=None)
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    signature = private_key.sign(
        _anchor_message(merkle_root_hex, image_sha256, finding_count)
    )
    return {
        "merkle_root": merkle_root_hex,
        "image_sha256": image_sha256,
        "finding_count": finding_count,
        "algorithm": _ANCHOR_ALGORITHM,
        "public_key_pem": public_pem.decode("utf-8"),
        "signature": signature.hex(),
    }


def verify_anchor(anchor: dict) -> bool:
    """Return True iff ``anchor`` is a valid Ed25519 seal over its bound fields.

    Publicly verifiable: uses only the ``public_key_pem`` embedded in the anchor.
    Returns False (never raises) on a swapped root, a rebound image, a forged
    count, a stranger's public key, or a malformed signature/key string.

    Raises:
        RuntimeError: if the ``cryptography`` package is not available.
    """
    signing._require_crypto()
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import serialization

    try:
        public_key = serialization.load_pem_public_key(
            anchor["public_key_pem"].encode("utf-8")
        )
        signature = bytes.fromhex(anchor["signature"])
        message = _anchor_message(
            anchor["merkle_root"],
            anchor["image_sha256"],
            anchor["finding_count"],
        )
        public_key.verify(signature, message)
        return True
    except (KeyError, ValueError, TypeError, AttributeError, InvalidSignature):
        return False
