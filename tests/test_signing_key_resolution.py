"""Key-resolution + public-key export branches (SFE-cahy, post-PR review).

Covers the error/fallback branches of ``resolve_signing_key`` and
``public_key_pem`` that the receipt tests exercised only indirectly - each is a
security-relevant guard on how the signer key is chosen, so a silent regression
(a pin that quietly degrades to HMAC, or an invalid pin that is trusted anyway)
must make a test go red.
"""

from __future__ import annotations

import pytest

import sift_find_evil.custody.signing as signing

crypto_only = pytest.mark.skipif(
    not signing.CRYPTOGRAPHY_AVAILABLE, reason="cryptography not installed"
)


# --- resolve_signing_key --------------------------------------------------------


@crypto_only
def test_unpinned_generates_a_fresh_ephemeral_key(monkeypatch):
    monkeypatch.delenv("SFE_RECEIPT_ED25519_KEY", raising=False)
    key, pinned = signing.resolve_signing_key()
    assert pinned is False
    assert isinstance(key, bytes) and b"PRIVATE KEY" in key
    # Ephemeral: a second call yields a different key.
    key2, _ = signing.resolve_signing_key()
    assert key2 != key


@crypto_only
def test_pinned_key_is_loaded_and_flagged_pinned(tmp_path, monkeypatch):
    priv, _pub = signing.generate_keypair()
    pem = tmp_path / "engine.pem"
    pem.write_bytes(priv)
    monkeypatch.setenv("SFE_RECEIPT_ED25519_KEY", str(pem))
    key, pinned = signing.resolve_signing_key()
    assert pinned is True
    assert key == priv  # the exact pinned bytes, not a fresh key


def test_unpinned_without_crypto_falls_back_to_none(monkeypatch):
    monkeypatch.delenv("SFE_RECEIPT_ED25519_KEY", raising=False)
    monkeypatch.setattr(signing, "CRYPTOGRAPHY_AVAILABLE", False)
    key, pinned = signing.resolve_signing_key()
    assert key is None and pinned is False


def test_pinned_without_crypto_raises_rather_than_degrading(tmp_path, monkeypatch):
    # A pin explicitly asks for signing; silently degrading to HMAC would hide it.
    pem = tmp_path / "engine.pem"
    pem.write_bytes(b"unused")
    monkeypatch.setenv("SFE_RECEIPT_ED25519_KEY", str(pem))
    monkeypatch.setattr(signing, "CRYPTOGRAPHY_AVAILABLE", False)
    with pytest.raises(RuntimeError, match="cryptography"):
        signing.resolve_signing_key()


@crypto_only
def test_pinned_path_missing_raises_valueerror(tmp_path, monkeypatch):
    monkeypatch.setenv("SFE_RECEIPT_ED25519_KEY", str(tmp_path / "nope.pem"))
    with pytest.raises(ValueError, match="not a readable Ed25519"):
        signing.resolve_signing_key()


@crypto_only
def test_pinned_invalid_pem_raises_valueerror(tmp_path, monkeypatch):
    bad = tmp_path / "bad.pem"
    bad.write_bytes(b"-----BEGIN PRIVATE KEY-----\ngarbage\n-----END PRIVATE KEY-----")
    monkeypatch.setenv("SFE_RECEIPT_ED25519_KEY", str(bad))
    with pytest.raises(ValueError, match="not a readable Ed25519"):
        signing.resolve_signing_key()


@crypto_only
def test_pinned_load_failure_does_not_leak_the_key_path(tmp_path, monkeypatch):
    """The load-failure message must not echo the signing-key file path.

    On a multi-user host, stderr can be shared/logged; leaking where the private
    key lives is needless disclosure (the key BYTES are never in the message -
    the failure fires before/at read - but the path should not be either).
    """
    secret_path = tmp_path / "super_secret_signing_key.pem"
    monkeypatch.setenv("SFE_RECEIPT_ED25519_KEY", str(secret_path))  # missing file
    with pytest.raises(ValueError) as exc:
        signing.resolve_signing_key()
    assert "super_secret_signing_key.pem" not in str(exc.value)
    assert str(secret_path) not in str(exc.value)


# --- public_key_pem -------------------------------------------------------------


@crypto_only
def test_public_key_pem_round_trips_with_generate_keypair():
    priv, pub = signing.generate_keypair()
    assert signing.public_key_pem(priv) == pub.decode("utf-8")


@crypto_only
def test_public_key_pem_raises_on_invalid_private_pem():
    with pytest.raises(ValueError):
        signing.public_key_pem(b"not-a-valid-pem")


def test_public_key_pem_raises_without_crypto(monkeypatch):
    monkeypatch.setattr(signing, "CRYPTOGRAPHY_AVAILABLE", False)
    with pytest.raises(RuntimeError, match="cryptography"):
        signing.public_key_pem(b"unused")
