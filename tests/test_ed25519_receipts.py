"""Tests for publicly-verifiable Ed25519 finding receipts.

Traces to the ed25519-receipts task: an upgrade path from the shared-secret
HMAC receipts in ``sift_find_evil/custody/receipt.py`` to signatures anyone can
verify with only the embedded public key.

Structure: Arrange-Act-Assert with inline synthetic findings and inverse
controls (tampered finding, tampered image hash, wrong keypair, malformed
signature).
"""

from __future__ import annotations

import pytest

from sift_find_evil.custody import signing

pytestmark = pytest.mark.skipif(
    not signing.CRYPTOGRAPHY_AVAILABLE,
    reason="cryptography not installed (optional connector dependency)",
)


def _finding() -> dict:
    """Return a synthetic finding dict for signing."""
    return {
        "title": "Ransomware note dropped",
        "finding_type": "indicator",
        "severity": "critical",
        "evidence": {"path": "C:/Users/victim/README.txt"},
    }


def test_generate_keypair_returns_pem_pair() -> None:
    # Arrange / Act
    private_pem, public_pem = signing.generate_keypair()

    # Assert
    assert isinstance(private_pem, bytes)
    assert isinstance(public_pem, bytes)
    assert b"PRIVATE KEY" in private_pem
    assert b"PUBLIC KEY" in public_pem


def test_sign_then_verify_true() -> None:
    # Arrange
    private_pem, _ = signing.generate_keypair()
    finding = _finding()

    # Act
    receipt = signing.sign_finding(
        finding, private_pem, image_sha256="a" * 64, tool="volatility3"
    )

    # Assert
    assert receipt["algorithm"] == "ed25519"
    assert receipt["tool"] == "volatility3"
    assert receipt["image_sha256"] == "a" * 64
    assert "PUBLIC KEY" in receipt["public_key_pem"]
    assert signing.verify_finding(finding, receipt) is True


def test_verify_needs_no_private_key() -> None:
    # Arrange: the receipt carries only the public key; no shared secret.
    private_pem, public_pem = signing.generate_keypair()
    finding = _finding()
    receipt = signing.sign_finding(
        finding, private_pem, image_sha256="b" * 64, tool="pecmd"
    )

    # Act / Assert: verification succeeds using the embedded public key alone.
    assert receipt["public_key_pem"] == public_pem.decode("utf-8")
    assert signing.verify_finding(finding, receipt) is True


def test_tampered_finding_fails() -> None:
    # Arrange
    private_pem, _ = signing.generate_keypair()
    finding = _finding()
    receipt = signing.sign_finding(
        finding, private_pem, image_sha256="c" * 64, tool="mftecmd"
    )

    # Act: mutate a copy of the finding after signing.
    tampered = {**finding, "severity": "low"}

    # Assert
    assert signing.verify_finding(tampered, receipt) is False


def test_tampered_image_sha256_fails() -> None:
    # Arrange
    private_pem, _ = signing.generate_keypair()
    finding = _finding()
    receipt = signing.sign_finding(
        finding, private_pem, image_sha256="d" * 64, tool="tshark"
    )

    # Act: rebind the receipt to a different evidence image.
    forged = {**receipt, "image_sha256": "e" * 64}

    # Assert
    assert signing.verify_finding(finding, forged) is False


def test_different_public_key_cannot_validate() -> None:
    # Arrange: sign with one keypair, swap in a stranger's public key.
    signer_private, _ = signing.generate_keypair()
    _, stranger_public = signing.generate_keypair()
    finding = _finding()
    receipt = signing.sign_finding(
        finding, signer_private, image_sha256="f" * 64, tool="recmd"
    )

    # Act
    forged = {**receipt, "public_key_pem": stranger_public.decode("utf-8")}

    # Assert
    assert signing.verify_finding(finding, forged) is False


def test_malformed_signature_returns_false_not_exception() -> None:
    # Arrange
    private_pem, _ = signing.generate_keypair()
    finding = _finding()
    receipt = signing.sign_finding(
        finding, private_pem, image_sha256="0" * 64, tool="evtxecmd"
    )

    # Act: corrupt the hex signature into non-hex garbage.
    forged = {**receipt, "signature": "not-hex-!!"}

    # Assert
    assert signing.verify_finding(finding, forged) is False


def test_malformed_public_key_returns_false() -> None:
    # Arrange
    private_pem, _ = signing.generate_keypair()
    finding = _finding()
    receipt = signing.sign_finding(
        finding, private_pem, image_sha256="1" * 64, tool="sleuthkit"
    )

    # Act: replace the public key PEM with garbage.
    forged = {**receipt, "public_key_pem": "-----BEGIN PUBLIC KEY-----\nnope\n"}

    # Assert
    assert signing.verify_finding(finding, forged) is False


def test_missing_receipt_field_returns_false() -> None:
    # Arrange
    private_pem, _ = signing.generate_keypair()
    finding = _finding()
    receipt = signing.sign_finding(
        finding, private_pem, image_sha256="2" * 64, tool="volatility3"
    )

    # Act: drop a bound field entirely.
    forged = {k: v for k, v in receipt.items() if k != "signature"}

    # Assert
    assert signing.verify_finding(finding, forged) is False


def test_functions_raise_when_cryptography_unavailable(monkeypatch) -> None:
    # Arrange: simulate cryptography not being installed.
    monkeypatch.setattr(signing, "CRYPTOGRAPHY_AVAILABLE", False)

    # Act / Assert
    with pytest.raises(RuntimeError, match="cryptography"):
        signing.generate_keypair()
    with pytest.raises(RuntimeError, match="cryptography"):
        signing.sign_finding({}, b"", image_sha256="x", tool="t")
    with pytest.raises(RuntimeError, match="cryptography"):
        signing.verify_finding({}, {})
