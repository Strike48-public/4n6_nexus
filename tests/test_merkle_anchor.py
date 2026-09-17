"""Merkle root over the finding set + a publicly-verifiable run anchor.

Move: receipts 4->5 (SFE-cahy). Per-finding Ed25519 receipts prove each finding
individually; the Merkle root binds the WHOLE finding set into one value, and the
signed anchor lets a third party prove offline (public key only, no shared
secret) that exactly these findings - no additions, deletions, or reorderings -
were emitted for this evidence image.

RED-first: sift_find_evil.custody.merkle did not exist.
"""

from __future__ import annotations

import hashlib

import pytest

from sift_find_evil.custody import merkle
from sift_find_evil.custody.signing import (
    CRYPTOGRAPHY_AVAILABLE,
    generate_keypair,
)

IMAGE = "a" * 64


def _leaf(n: int) -> str:
    """A stand-in finding hash (any 64-hex string works as a Merkle leaf)."""
    return hashlib.sha256(f"finding-{n}".encode()).hexdigest()


# --- Merkle tree hash (pure stdlib, RFC 6962 shape) ----------------------------


def test_empty_set_has_defined_empty_root():
    # RFC 6962: MTH({}) = SHA-256 of the empty string.
    assert merkle.merkle_root([]) == hashlib.sha256(b"").hexdigest()


def test_single_leaf_is_domain_separated_not_the_bare_hash():
    # A one-finding tree must NOT equal the raw finding hash - the 0x00 leaf
    # prefix (second-preimage hardening) makes them differ.
    leaf = _leaf(1)
    root = merkle.merkle_root([leaf])
    assert root != leaf
    assert root == hashlib.sha256(b"\x00" + bytes.fromhex(leaf)).hexdigest()


def test_root_is_deterministic_for_a_given_ordered_set():
    leaves = [_leaf(i) for i in range(5)]
    assert merkle.merkle_root(leaves) == merkle.merkle_root(list(leaves))


def test_reordering_changes_the_root():
    leaves = [_leaf(i) for i in range(4)]
    reordered = [leaves[1], leaves[0], leaves[2], leaves[3]]
    assert merkle.merkle_root(leaves) != merkle.merkle_root(reordered)


def test_adding_a_finding_changes_the_root():
    leaves = [_leaf(i) for i in range(3)]
    assert merkle.merkle_root(leaves) != merkle.merkle_root(leaves + [_leaf(99)])


def test_removing_a_finding_changes_the_root():
    leaves = [_leaf(i) for i in range(3)]
    assert merkle.merkle_root(leaves) != merkle.merkle_root(leaves[:-1])


def test_odd_leaf_count_is_handled():
    # Three leaves (odd) must produce a stable, non-error root.
    leaves = [_leaf(i) for i in range(3)]
    root = merkle.merkle_root(leaves)
    assert isinstance(root, str) and len(root) == 64


# --- Signed run anchor (Ed25519, publicly verifiable) --------------------------

pytestmark_crypto = pytest.mark.skipif(
    not CRYPTOGRAPHY_AVAILABLE, reason="cryptography not installed"
)


@pytestmark_crypto
def test_anchor_round_trips():
    priv, _pub = generate_keypair()
    leaves = [_leaf(i) for i in range(4)]
    root = merkle.merkle_root(leaves)
    anchor = merkle.mint_anchor(root, IMAGE, len(leaves), priv)
    assert anchor["merkle_root"] == root
    assert anchor["image_sha256"] == IMAGE
    assert anchor["finding_count"] == 4
    assert anchor["algorithm"] == "ed25519"
    # Publicly verifiable with only the receipt (no private key / shared secret).
    assert merkle.verify_anchor(anchor) is True


@pytestmark_crypto
def test_anchor_detects_a_swapped_root():
    priv, _pub = generate_keypair()
    anchor = merkle.mint_anchor(_leaf(0), IMAGE, 1, priv)
    forged = {**anchor, "merkle_root": _leaf(1)}
    assert merkle.verify_anchor(forged) is False


@pytestmark_crypto
def test_anchor_detects_a_rebound_image():
    priv, _pub = generate_keypair()
    anchor = merkle.mint_anchor(_leaf(0), IMAGE, 1, priv)
    forged = {**anchor, "image_sha256": "b" * 64}
    assert merkle.verify_anchor(forged) is False


@pytestmark_crypto
def test_anchor_detects_a_forged_count():
    priv, _pub = generate_keypair()
    anchor = merkle.mint_anchor(_leaf(0), IMAGE, 1, priv)
    forged = {**anchor, "finding_count": 99}
    assert merkle.verify_anchor(forged) is False


@pytestmark_crypto
def test_anchor_rejects_a_stranger_public_key():
    signer_priv, _ = generate_keypair()
    _, stranger_pub = generate_keypair()
    anchor = merkle.mint_anchor(_leaf(0), IMAGE, 1, signer_priv)
    forged = {**anchor, "public_key_pem": stranger_pub.decode("utf-8")}
    assert merkle.verify_anchor(forged) is False


@pytestmark_crypto
def test_anchor_verify_never_raises_on_garbage():
    assert merkle.verify_anchor({}) is False
    assert merkle.verify_anchor({"signature": "not-hex"}) is False
