"""Publicly-verifiable Ed25519 finding receipts (upgrade path from HMAC).

This is the asymmetric-signature sibling of ``sift_find_evil/custody/receipt.py``.
Where the HMAC receipts require a shared per-run secret to *verify*, these
receipts embed the signer's Ed25519 public key, so any third party (a court, an
auditor, a downstream 4n6nexus consumer) can verify a finding was produced by
the holder of the private key using only the receipt itself.

The receipt binds three things under one signature:

  * ``finding_hash``   - SHA-256 over the finding's canonical JSON (identity)
  * ``image_sha256``   - the evidence image the run was performed against
  * ``tool``           - the provenance that produced the finding

Editing the finding body, rebinding the image hash, swapping the provenance, or
substituting a stranger's public key all change the verified message (or the
verifying key) and fail verification.

``cryptography`` is an optional dependency (the connector extra), so it is
imported lazily inside the functions: the core ``sift_find_evil`` package still
imports cleanly when it is absent, and the signing feature raises a clear
``RuntimeError`` only when actually invoked.
"""

from __future__ import annotations

import hashlib
import json

try:  # pragma: no cover - trivial availability probe
    import cryptography  # noqa: F401

    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised via monkeypatch in tests
    CRYPTOGRAPHY_AVAILABLE = False

_ALGORITHM = "ed25519"
_UNAVAILABLE_MSG = (
    "Ed25519 finding receipts require the 'cryptography' package "
    "(install the connector extra); it is not available in this environment."
)


def _require_crypto() -> None:
    """Raise a clear error if the signing feature is used without cryptography.

    Raises:
        RuntimeError: if the ``cryptography`` package is not installed.
    """
    if not CRYPTOGRAPHY_AVAILABLE:
        raise RuntimeError(_UNAVAILABLE_MSG)


def _canonical(payload: dict) -> bytes:
    """Serialize ``payload`` to reproducible canonical UTF-8 JSON bytes.

    Args:
        payload: Any JSON-serializable mapping.

    Returns:
        Canonical JSON bytes: keys sorted, tight separators.
    """
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), default=str
    ).encode("utf-8")


def _finding_hash(finding: dict) -> str:
    """Return the SHA-256 hex digest over the finding's canonical content."""
    return hashlib.sha256(_canonical(finding)).hexdigest()


def _signed_message(finding_hash: str, image_sha256: str, tool: str) -> bytes:
    """Return the exact bytes the Ed25519 signature is computed over.

    Binds the finding identity, the evidence image, and the tool provenance so
    none of them can be altered without invalidating the signature.
    """
    return _canonical(
        {
            "finding_hash": finding_hash,
            "image_sha256": image_sha256,
            "tool": tool,
        }
    )


def generate_keypair() -> tuple[bytes, bytes]:
    """Generate a fresh Ed25519 keypair as PEM byte strings.

    Returns:
        A ``(private_pem, public_pem)`` tuple. The private key is
        PKCS#8/PEM (unencrypted); the public key is SubjectPublicKeyInfo/PEM.

    Raises:
        RuntimeError: if the ``cryptography`` package is not available.
    """
    _require_crypto()
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519

    private_key = ed25519.Ed25519PrivateKey.generate()
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, public_pem


def sign_finding(
    finding: dict, private_pem: bytes, image_sha256: str, tool: str
) -> dict:
    """Mint a publicly-verifiable Ed25519 receipt for ``finding``.

    Args:
        finding: The finding content (any JSON-serializable dict).
        private_pem: The signer's PEM-encoded Ed25519 private key.
        image_sha256: SHA-256 of the evidence image this run analyzed.
        tool: Name of the forensic tool that produced the finding.

    Returns:
        A receipt dict with keys ``finding_hash``, ``image_sha256``, ``tool``,
        ``algorithm`` (``"ed25519"``), ``public_key_pem``, and ``signature``
        (hex). The receipt is self-contained: verification needs no secret.

    Raises:
        RuntimeError: if the ``cryptography`` package is not available.
    """
    _require_crypto()
    from cryptography.hazmat.primitives import serialization

    private_key = serialization.load_pem_private_key(private_pem, password=None)
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    fh = _finding_hash(finding)
    signature = private_key.sign(_signed_message(fh, image_sha256, tool))
    return {
        "finding_hash": fh,
        "image_sha256": image_sha256,
        "tool": tool,
        "algorithm": _ALGORITHM,
        "public_key_pem": public_pem.decode("utf-8"),
        "signature": signature.hex(),
    }


def verify_finding(finding: dict, receipt: dict) -> bool:
    """Return True iff ``receipt`` is a valid Ed25519 seal over ``finding``.

    Publicly verifiable: uses only the ``public_key_pem`` embedded in the
    receipt (no shared secret). Recomputes the finding hash from the presented
    finding and verifies the signature over the same canonical message.

    Returns False (never raises) on a tampered finding, a rebound image hash or
    provenance, a swapped public key, or a malformed signature/key string.

    Args:
        finding: The finding content presented for verification.
        receipt: A receipt produced by :func:`sign_finding`.

    Returns:
        True if the receipt authenticates the finding, False otherwise.

    Raises:
        RuntimeError: if the ``cryptography`` package is not available.
    """
    _require_crypto()
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import serialization

    try:
        # The finding presented now must hash to the receipt's bound identity.
        if _finding_hash(finding) != receipt.get("finding_hash"):
            return False

        public_key = serialization.load_pem_public_key(
            receipt["public_key_pem"].encode("utf-8")
        )
        signature = bytes.fromhex(receipt["signature"])
        message = _signed_message(
            receipt["finding_hash"],
            receipt["image_sha256"],
            receipt["tool"],
        )
        public_key.verify(signature, message)
        return True
    except (KeyError, ValueError, TypeError, AttributeError, InvalidSignature):
        return False
