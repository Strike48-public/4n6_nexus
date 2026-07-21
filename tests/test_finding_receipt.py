"""Tests for cryptographic finding receipts (gallery idea #4).

Each finding is bound to a signed envelope carrying the evidence-image SHA-256,
the tool provenance, and a hash of the finding's own content. Only code holding
the per-run key can mint a receipt, so a hallucinated finding (one the engine
never produced) literally has no valid receipt. Tampering with the finding body,
the bound image hash, or the provenance breaks verification.

Reuses the HMAC-SHA256 canonical-JSON convention already proven in
sift_find_evil/approval/manager.py.

RED-first: sift_find_evil.custody.receipt did not exist before.
"""

import pytest

from sift_find_evil.custody.receipt import (
    ReceiptMinter,
    mint_receipt,
    verify_receipt,
)


KEY = b"0" * 32
IMAGE_SHA = "a" * 64


def _finding_dict(title="Ransomware execution", severity="critical"):
    return {
        "title": title,
        "severity": severity,
        "category": "execution",
        "evidence": {"executable": "evil.exe", "pid": 4242},
    }


def test_mint_produces_receipt_with_bound_fields():
    r = mint_receipt(
        _finding_dict(),
        key=KEY,
        image_sha256=IMAGE_SHA,
        tool="mftecmd",
        tool_version="1.2.0",
    )
    assert r["image_sha256"] == IMAGE_SHA
    assert r["tool"] == "mftecmd"
    assert r["tool_version"] == "1.2.0"
    assert len(r["signature"]) == 64  # hex HMAC-SHA256
    assert len(r["finding_hash"]) == 64


def test_valid_receipt_verifies():
    f = _finding_dict()
    r = mint_receipt(f, key=KEY, image_sha256=IMAGE_SHA, tool="mftecmd")
    assert verify_receipt(f, r, key=KEY) is True


def test_tampered_finding_body_fails():
    f = _finding_dict()
    r = mint_receipt(f, key=KEY, image_sha256=IMAGE_SHA, tool="mftecmd")
    # Attacker edits the finding after it was sealed.
    f_tampered = _finding_dict(title="Totally benign", severity="low")
    assert verify_receipt(f_tampered, r, key=KEY) is False


def test_tampered_image_binding_fails():
    f = _finding_dict()
    r = mint_receipt(f, key=KEY, image_sha256=IMAGE_SHA, tool="mftecmd")
    r_tampered = {**r, "image_sha256": "b" * 64}
    assert verify_receipt(f, r_tampered, key=KEY) is False


def test_wrong_key_fails():
    f = _finding_dict()
    r = mint_receipt(f, key=KEY, image_sha256=IMAGE_SHA, tool="mftecmd")
    assert verify_receipt(f, r, key=b"1" * 32) is False


def test_forged_signature_is_rejected_not_crashed():
    f = _finding_dict()
    r = mint_receipt(f, key=KEY, image_sha256=IMAGE_SHA, tool="mftecmd")
    # Non-hex / wrong-length signature must be a clean False, not an exception.
    assert verify_receipt(f, {**r, "signature": "not-a-real-hmac"}, key=KEY) is False


def test_receipt_copied_between_findings_fails():
    f1 = _finding_dict(title="Finding one")
    f2 = _finding_dict(title="Finding two")
    r1 = mint_receipt(f1, key=KEY, image_sha256=IMAGE_SHA, tool="mftecmd")
    # A receipt minted for f1 must not validate f2 (finding_hash binds identity).
    assert verify_receipt(f2, r1, key=KEY) is False


def test_short_key_refused_at_mint():
    with pytest.raises(ValueError):
        mint_receipt(_finding_dict(), key=b"tooshort", image_sha256=IMAGE_SHA, tool="x")


def test_minter_uses_run_scoped_key_and_image():
    minter = ReceiptMinter(key=KEY, image_sha256=IMAGE_SHA)
    f = _finding_dict()
    r = minter.mint(f, tool="pecmd", tool_version="0.9")
    assert r["image_sha256"] == IMAGE_SHA
    assert minter.verify(f, r) is True
    assert minter.verify(_finding_dict(title="other"), r) is False


def test_verify_with_short_key_returns_false():
    # Covers the short-key guard in verify_receipt (never raises).
    f = _finding_dict()
    r = mint_receipt(f, key=KEY, image_sha256=IMAGE_SHA, tool="mftecmd")
    assert verify_receipt(f, r, key=b"tooshort") is False


def test_verify_correct_length_but_non_hex_signature_returns_false():
    # 64 chars long (passes the length check) but not hex -> clean False.
    f = _finding_dict()
    r = mint_receipt(f, key=KEY, image_sha256=IMAGE_SHA, tool="mftecmd")
    assert verify_receipt(f, {**r, "signature": "z" * 64}, key=KEY) is False


def test_verify_non_bytes_key_is_caught_not_crashed():
    # A str key of valid length passes the len() guard but hmac.new rejects a
    # non-bytes key with TypeError; verify_receipt must swallow it as False.
    f = _finding_dict()
    r = mint_receipt(f, key=KEY, image_sha256=IMAGE_SHA, tool="mftecmd")
    assert verify_receipt(f, r, key="x" * 32) is False


def test_minter_short_key_refused_at_construction():
    with pytest.raises(ValueError):
        ReceiptMinter(key=b"tooshort", image_sha256=IMAGE_SHA)
