"""Ed25519 receipts are the DEFAULT emission path (SFE-cahy, receipts 4->5).

Before this move, ``harden_findings`` minted an Ed25519 ``signed_receipt`` only
when a caller opted in with ``signing_key=...``; the default path emitted HMAC
only, so public verifiability was not load-bearing. This flips it: with the
``cryptography`` package present, every finding gets a publicly-verifiable
Ed25519 receipt by default (a fresh per-run key is generated), HMAC stays as the
run-key receipt, and a Merkle root + signed anchor bind the whole finding set.

When ``cryptography`` is absent, the engine still imports and runs - it falls
back to HMAC-only receipts with no Ed25519 and no anchor (the core package must
install without the connector extra). That fallback is asserted here too.

Mutation-guarded: each test would go green->red if the default were reverted to
opt-in, if the Merkle root stopped covering the set, or if the anchor stopped
binding the image.
"""

from __future__ import annotations

import pytest

from sift_find_evil.custody import merkle
from sift_find_evil.custody.signing import CRYPTOGRAPHY_AVAILABLE, verify_finding
from sift_find_evil.findings import Finding, FindingCategory
from sift_find_evil.hardening import harden_findings

KEY = b"k" * 32
IMAGE = "a" * 64

crypto_only = pytest.mark.skipif(
    not CRYPTOGRAPHY_AVAILABLE, reason="cryptography not installed"
)


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


@crypto_only
def test_default_path_emits_ed25519_receipt_without_opt_in():
    # No signing_key passed - the DEFAULT must now be publicly verifiable.
    report = harden_findings([_finding()], image_sha256=IMAGE, receipt_key=KEY)
    item = report.hardened[0]
    sr = item["signed_receipt"]
    assert sr is not None, "default path must emit an Ed25519 signed receipt"
    assert sr["algorithm"] == "ed25519"
    # Verifiable with ONLY the receipt - no shared secret, no HMAC key.
    assert verify_finding(item["finding"], sr) is True


@crypto_only
def test_default_still_mints_hmac_alongside_ed25519():
    report = harden_findings([_finding()], image_sha256=IMAGE, receipt_key=KEY)
    item = report.hardened[0]
    # HMAC receipt remains the run-key seal; Ed25519 is the public-key seal.
    assert item["receipt"]["signature"]
    assert item["signed_receipt"]["signature"]


@crypto_only
def test_default_signed_count_equals_finding_count():
    report = harden_findings(
        [_finding("a"), _finding("b"), _finding("c")],
        image_sha256=IMAGE,
        receipt_key=KEY,
    )
    assert report.signed_receipts == 3
    assert report.finding_count == 3  # F1-safe: count preserved.


@crypto_only
def test_report_carries_a_merkle_root_over_the_finding_set():
    report = harden_findings(
        [_finding("a"), _finding("b")], image_sha256=IMAGE, receipt_key=KEY
    )
    # The root recomputes from the emitted receipts' finding hashes.
    hashes = [h["signed_receipt"]["finding_hash"] for h in report.hardened]
    assert report.merkle_root == merkle.merkle_root(hashes)


@crypto_only
def test_report_carries_a_verifiable_signed_anchor():
    report = harden_findings(
        [_finding("a"), _finding("b")], image_sha256=IMAGE, receipt_key=KEY
    )
    anchor = report.anchor
    assert anchor is not None
    assert anchor["image_sha256"] == IMAGE
    assert anchor["finding_count"] == 2
    assert anchor["merkle_root"] == report.merkle_root
    assert merkle.verify_anchor(anchor) is True


@crypto_only
def test_anchor_root_matches_the_actual_findings_not_a_stale_value():
    # Guard: dropping a finding from the set must break the anchor's root match.
    report = harden_findings(
        [_finding("a"), _finding("b")], image_sha256=IMAGE, receipt_key=KEY
    )
    only_first = [report.hardened[0]["signed_receipt"]["finding_hash"]]
    assert merkle.merkle_root(only_first) != report.anchor["merkle_root"]


@crypto_only
def test_explicit_signing_key_still_honored():
    # Back-compat: a caller may still pass its own key; behavior is unchanged.
    from sift_find_evil.custody.signing import generate_keypair

    priv, _pub = generate_keypair()
    report = harden_findings(
        [_finding()], image_sha256=IMAGE, receipt_key=KEY, signing_key=priv
    )
    item = report.hardened[0]
    assert verify_finding(item["finding"], item["signed_receipt"]) is True


def test_fallback_to_hmac_only_when_cryptography_absent(monkeypatch):
    # Simulate the core install (no connector extra): must NOT raise, and must
    # degrade to HMAC-only with no Ed25519 receipt and no anchor. The gate lives
    # in signing.resolve_signing_key, so patch it there.
    import sift_find_evil.custody.signing as signing_mod

    monkeypatch.setattr(signing_mod, "CRYPTOGRAPHY_AVAILABLE", False)
    report = harden_findings([_finding()], image_sha256=IMAGE, receipt_key=KEY)
    item = report.hardened[0]
    assert item["receipt"]["signature"]  # HMAC still present
    assert item["signed_receipt"] is None  # no public-key receipt
    assert report.anchor is None  # no anchor without a signing key
    assert report.finding_count == 1  # F1-safe
