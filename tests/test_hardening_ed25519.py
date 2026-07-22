"""Ed25519 publicly-verifiable receipts wired into hardening (move #4).

The HMAC receipt binds a finding but is verifiable only by the run-key holder.
The Ed25519 receipt (custody/signing.py) is publicly verifiable - anyone can
check it with only the embedded public key, no shared secret. This wires it into
the hardening pipeline as an optional signed receipt per finding, giving 4n6
Nexus the public-key parity the field-best receipt holders (OATH/Stigmergy/
VERDICT) have. Additive and opt-in (only when a signing key is supplied), so the
default path and F1 are unchanged.

RED-first: harden_findings had no signing_key parameter.
"""

import pytest

from sift_find_evil.custody.signing import (
    CRYPTOGRAPHY_AVAILABLE,
    generate_keypair,
    verify_finding,
)
from sift_find_evil.findings import Finding, FindingCategory
from sift_find_evil.hardening import harden_findings

pytestmark = pytest.mark.skipif(
    not CRYPTOGRAPHY_AVAILABLE, reason="cryptography not installed"
)

KEY = b"k" * 32
IMAGE = "a" * 64


def _finding(title="evil.exe"):
    return Finding(
        title=title,
        description="d",
        finding_type="indicator",
        severity="high",
        category=FindingCategory.EXECUTION,
        evidence={"executable": "evil.exe"},
        confidence=0.9,
        artifact_sources=["MFT", "Prefetch"],
    )


def test_no_signing_key_means_no_signed_receipt():
    report = harden_findings([_finding()], image_sha256=IMAGE, receipt_key=KEY)
    # Default path unchanged: HMAC receipt present, no Ed25519 signed receipt.
    assert report.hardened[0].get("signed_receipt") is None


def test_signing_key_adds_publicly_verifiable_receipt():
    priv, _pub = generate_keypair()
    report = harden_findings(
        [_finding()], image_sha256=IMAGE, receipt_key=KEY, signing_key=priv
    )
    item = report.hardened[0]
    sr = item["signed_receipt"]
    assert sr is not None
    assert sr["algorithm"] == "ed25519"
    assert "public_key_pem" in sr
    # Publicly verifiable: verify with ONLY the receipt (no private key, no HMAC key).
    assert verify_finding(item["finding"], sr) is True


def test_signed_receipt_detects_tampering():
    priv, _pub = generate_keypair()
    report = harden_findings(
        [_finding()], image_sha256=IMAGE, receipt_key=KEY, signing_key=priv
    )
    item = report.hardened[0]
    forged = {**item["finding"], "severity": "info", "title": "benign"}
    assert verify_finding(forged, item["signed_receipt"]) is False


def test_signed_count_surfaced_in_report():
    priv, _pub = generate_keypair()
    report = harden_findings(
        [_finding("a"), _finding("b")],
        image_sha256=IMAGE,
        receipt_key=KEY,
        signing_key=priv,
    )
    assert report.signed_receipts == 2
    # Still F1-safe: finding count unchanged.
    assert report.finding_count == 2


def test_hmac_receipt_still_present_alongside_signed():
    priv, _pub = generate_keypair()
    report = harden_findings(
        [_finding()], image_sha256=IMAGE, receipt_key=KEY, signing_key=priv
    )
    item = report.hardened[0]
    # Both receipts coexist: HMAC (run-key) + Ed25519 (public-key).
    assert item["receipt"]["signature"]
    assert item["signed_receipt"]["signature"]
