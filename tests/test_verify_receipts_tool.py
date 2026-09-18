"""Offline receipt+anchor verifier (tools/verify_receipts.py) - SFE-cahy.

Companion to tools/verify_chain.py (which verifies the audit hash-chain). This
one verifies the finding RECEIPTS: it re-implements canonical JSON, the finding
hash, and the RFC 6962 Merkle root from the stdlib, and checks each Ed25519
receipt + the run anchor using ONLY the public keys embedded in the report. Like
verify_chain, it imports nothing from sift_find_evil, so a third party (a court,
an auditor) can prove a report's findings offline without trusting or installing
the engine.

The tool is exercised end-to-end against a report the real hardening pipeline
produced, so writer/reader canonicalization drift fails a pristine report here.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

from sift_find_evil.custody.signing import CRYPTOGRAPHY_AVAILABLE
from sift_find_evil.findings import Finding, FindingCategory
from sift_find_evil.hardening import harden_findings

pytestmark = pytest.mark.skipif(
    not CRYPTOGRAPHY_AVAILABLE, reason="cryptography not installed"
)

REPO_ROOT = Path(__file__).resolve().parents[1]
TOOL_PATH = REPO_ROOT / "tools" / "verify_receipts.py"


def _load_tool():
    """Import the standalone verifier by path (it lives outside the package)."""
    spec = importlib.util.spec_from_file_location("verify_receipts", TOOL_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


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


def _report_dict(findings):
    return harden_findings(
        findings, image_sha256="a" * 64, receipt_key=b"k" * 32
    ).to_dict()


def _write(tmp_path, report) -> str:
    p = tmp_path / "hardening_report.json"
    p.write_text(json.dumps(report), encoding="utf-8")
    return str(p)


def test_tool_file_exists():
    assert TOOL_PATH.exists(), "tools/verify_receipts.py must exist"


def test_clean_report_verifies_ok(tmp_path):
    mod = _load_tool()
    report = _report_dict([_finding("a"), _finding("b")])
    code, msg = mod.verify(_write(tmp_path, report))
    assert code == 0, msg
    assert "OK" in msg


def test_missing_file_is_exit_2(tmp_path):
    mod = _load_tool()
    code, _msg = mod.verify(str(tmp_path / "nope.json"))
    assert code == 2


def test_tampered_finding_body_fails(tmp_path):
    mod = _load_tool()
    report = _report_dict([_finding("a")])
    # Edit the finding after signing - its recomputed hash no longer matches.
    report["hardened"][0]["finding"]["severity"] = "info"
    code, msg = mod.verify(_write(tmp_path, report))
    assert code == 1
    assert "finding" in msg.lower() or "hash" in msg.lower()


def test_dropped_finding_breaks_merkle_root(tmp_path):
    mod = _load_tool()
    report = _report_dict([_finding("a"), _finding("b")])
    # Drop the second finding but keep the anchor's root - set-level tamper.
    report["hardened"] = report["hardened"][:1]
    code, msg = mod.verify(_write(tmp_path, report))
    assert code == 1
    assert "merkle" in msg.lower() or "anchor" in msg.lower()


def test_reordered_findings_break_merkle_root(tmp_path):
    mod = _load_tool()
    report = _report_dict([_finding("a"), _finding("b"), _finding("c")])
    h = report["hardened"]
    report["hardened"] = [h[2], h[1], h[0]]
    code, msg = mod.verify(_write(tmp_path, report))
    assert code == 1


def test_swapped_public_key_on_a_receipt_fails(tmp_path):
    mod = _load_tool()
    from sift_find_evil.custody.signing import generate_keypair

    report = _report_dict([_finding("a")])
    _, stranger_pub = generate_keypair()
    report["hardened"][0]["signed_receipt"]["public_key_pem"] = stranger_pub.decode(
        "utf-8"
    )
    code, _msg = mod.verify(_write(tmp_path, report))
    assert code == 1


def test_forged_anchor_signature_fails(tmp_path):
    mod = _load_tool()
    report = _report_dict([_finding("a")])
    report["anchor"]["signature"] = "00" * 64
    code, msg = mod.verify(_write(tmp_path, report))
    assert code == 1
    assert "anchor" in msg.lower()


# --- Adversarial: the two set-level splices the reviewer demonstrated ----------


def test_drop_finding_then_reanchor_with_new_key_is_rejected(tmp_path):
    """Splice attack: keep the original engine-signed receipts, delete one
    finding, and re-mint ONLY the anchor with the attacker's own key so the root
    matches the shortened set. Caught by the anchor-signer check (the anchor key
    is not among the receipt signers), no trusted key needed.
    """
    from sift_find_evil.custody import merkle
    from sift_find_evil.custody.signing import generate_keypair

    mod = _load_tool()
    report = _report_dict([_finding("a"), _finding("b")])
    # Drop the second finding (its receipt is still signed by the engine key).
    report["hardened"] = report["hardened"][:1]
    kept = [report["hardened"][0]["signed_receipt"]["finding_hash"]]
    attacker_priv, _ = generate_keypair()
    new_root = merkle.merkle_root(kept)
    # Re-anchor over the shortened set with the ATTACKER's key: root + count now
    # self-consistent, signature valid under the attacker key.
    report["anchor"] = merkle.mint_anchor(new_root, "a" * 64, 1, attacker_priv)
    code, msg = mod.verify(_write(tmp_path, report))
    assert code == 1
    assert "signer" in msg.lower() or "different key" in msg.lower()


def test_receipts_signed_by_two_different_keys_is_rejected(tmp_path):
    """Mixed-signer splice: two receipts signed by DIFFERENT keys (same image,
    anchor by one of them) must be rejected. Uniquely guards the
    ``len(signer_ders) > 1`` check - distinct from the anchor-signer check above,
    which only compares the anchor key to the receipt signers.
    """
    from sift_find_evil.custody import merkle
    from sift_find_evil.custody.signing import generate_keypair, sign_finding

    mod = _load_tool()
    k1, _ = generate_keypair()
    k2, _ = generate_keypair()
    f_a = _finding("a")
    f_b = _finding("b")
    ra = sign_finding(f_a.to_dict(), k1, "a" * 64, "engine")
    rb = sign_finding(f_b.to_dict(), k2, "a" * 64, "engine")  # different signer
    anchor = merkle.mint_anchor(
        merkle.merkle_root([ra["finding_hash"], rb["finding_hash"]]),
        "a" * 64,
        2,
        k1,
    )
    report = {
        "hardened": [
            {"finding": f_a.to_dict(), "signed_receipt": ra},
            {"finding": f_b.to_dict(), "signed_receipt": rb},
        ],
        "anchor": anchor,
    }
    code, msg = mod.verify(_write(tmp_path, report))
    assert code == 1
    assert "more than one key" in msg.lower() or "signer" in msg.lower()


def test_fully_fabricated_report_rejected_when_trusted_key_pinned(tmp_path):
    """Fabricate-from-scratch: an attacker mints an entirely new, internally
    consistent report with their own key. It passes WITHOUT a trusted key
    (internal consistency only), but MUST fail when the engine's real public key
    is supplied as the trust root.
    """
    from sift_find_evil.custody.signing import generate_keypair, public_key_pem

    mod = _load_tool()
    # A report signed by a key that is NOT the engine's published key.
    fabricated = _report_dict([_finding("evil")])
    engine_priv, _ = generate_keypair()
    trusted_pem = public_key_pem(engine_priv)  # the real engine's published key

    path = _write(tmp_path, fabricated)
    # No trusted key: internal consistency holds, so it verifies.
    assert mod.verify(path)[0] == 0
    # With the engine's trusted key: provenance check fails.
    code, msg = mod.verify(path, trusted_pubkey_pem=trusted_pem)
    assert code == 1
    assert "trusted" in msg.lower() or "provenance" in msg.lower()


def test_matching_trusted_key_verifies_provenance(tmp_path, monkeypatch):
    """When the report is signed by a PINNED key and the same public key is given
    as the trust root, provenance verifies (exit 0, message says so)."""
    import sift_find_evil.custody.signing as signing

    mod = _load_tool()
    priv, _ = signing.generate_keypair()
    pinned = tmp_path / "engine_key.pem"
    pinned.write_bytes(priv)
    monkeypatch.setenv("SFE_RECEIPT_ED25519_KEY", str(pinned))
    # Report is now signed by the pinned key (resolve_signing_key reads the env).
    report = _report_dict([_finding("a"), _finding("b")])
    trusted_pem = signing.public_key_pem(priv)
    code, msg = mod.verify(_write(tmp_path, report), trusted_pubkey_pem=trusted_pem)
    assert code == 0, msg
    assert "provenance verified" in msg.lower()


def test_reads_orchestrator_case_findings_shape(tmp_path):
    """HIGH #2: the tool must read a live orchestrator report (case_findings),
    not only a hardening report (hardened)."""
    mod = _load_tool()
    hardening = _report_dict([_finding("a"), _finding("b")])
    # Project to the orchestrator's shape: findings under case_findings.
    orch_report = {
        "case_findings": hardening["hardened"],
        "anchor": hardening["anchor"],
    }
    code, msg = mod.verify(_write(tmp_path, orch_report))
    assert code == 0, msg


def test_hmac_only_report_is_exit_3_not_broken(tmp_path, monkeypatch):
    """LOW: an honest HMAC-only report (no Ed25519) is exit 3, not 'BROKEN'."""
    import sift_find_evil.custody.signing as signing

    mod = _load_tool()
    # Force the HMAC-only fallback path (the signing gate lives here).
    monkeypatch.setattr(signing, "CRYPTOGRAPHY_AVAILABLE", False)
    report = _report_dict([_finding("a")])
    assert report["hardened"][0]["signed_receipt"] is None
    code, msg = mod.verify(_write(tmp_path, report))
    assert code == 3
    assert "hmac" in msg.lower()


# --- Round-2 review: anchor-strip, cross-image splice, total-wipe --------------


def test_drop_finding_then_strip_anchor_is_rejected(tmp_path):
    """Round-2 HIGH: dropping a finding AND deleting the anchor must not pass.
    The engine always emits an anchor with Ed25519 receipts, so receipts-without-
    anchor is a tamper signature, not a legitimate shape.
    """
    mod = _load_tool()
    report = _report_dict([_finding("a"), _finding("b")])
    report["hardened"] = report["hardened"][:1]  # drop finding 'b'
    del report["anchor"]  # strip the set-level binding
    code, msg = mod.verify(_write(tmp_path, report))
    assert code == 1
    assert "anchor" in msg.lower()


def test_null_anchor_with_receipts_is_rejected(tmp_path):
    """anchor: null must be treated the same as a missing anchor (rejected)."""
    mod = _load_tool()
    report = _report_dict([_finding("a")])
    report["anchor"] = None
    code, msg = mod.verify(_write(tmp_path, report))
    assert code == 1


def test_cross_image_receipt_splice_is_rejected(tmp_path):
    """Round-2 HIGH: receipts bound to two different evidence images must not
    verify as one coherent set, even under a matching anchor signer."""
    from sift_find_evil.custody import merkle
    from sift_find_evil.custody.signing import generate_keypair, sign_finding

    mod = _load_tool()
    priv, _ = generate_keypair()
    # Two receipts under ONE key but bound to DIFFERENT images.
    f_a = _finding("a")
    f_b = _finding("b")
    ra = sign_finding(f_a.to_dict(), priv, "a" * 64, "engine")
    rb = sign_finding(f_b.to_dict(), priv, "b" * 64, "engine")  # different image
    hashes = [ra["finding_hash"], rb["finding_hash"]]
    anchor = merkle.mint_anchor(merkle.merkle_root(hashes), "a" * 64, 2, priv)
    report = {
        "hardened": [
            {"finding": f_a.to_dict(), "signed_receipt": ra},
            {"finding": f_b.to_dict(), "signed_receipt": rb},
        ],
        "anchor": anchor,
    }
    code, msg = mod.verify(_write(tmp_path, report))
    assert code == 1
    assert "image" in msg.lower()


def test_anchor_image_mismatch_is_rejected(tmp_path):
    """The anchor's image must equal the receipts' image (single evidence run).

    A receipt bound to image A must not verify under a (self-consistent) anchor
    bound to image B - both signed by the same key.
    """
    from sift_find_evil.custody import merkle
    from sift_find_evil.custody.signing import generate_keypair, sign_finding

    mod = _load_tool()
    priv, _ = generate_keypair()
    f = _finding("a")
    ra = sign_finding(f.to_dict(), priv, "a" * 64, "engine")  # receipt on image A
    report = {
        "hardened": [{"finding": f.to_dict(), "signed_receipt": ra}],
        # Coherent anchor, same signer, but bound to image B.
        "anchor": merkle.mint_anchor(
            merkle.merkle_root([ra["finding_hash"]]), "b" * 64, 1, priv
        ),
    }
    code, msg = mod.verify(_write(tmp_path, report))
    assert code == 1
    assert "image" in msg.lower()


def test_total_wipe_reanchor_passes_without_key_but_flagged(tmp_path):
    """Total wipe (0 findings) + attacker re-anchor: with NO trusted key it can't
    be distinguished from a clean run, so it verifies - but the message must NOT
    claim 'finding set intact', and a trusted key must reject it."""
    from sift_find_evil.custody import merkle
    from sift_find_evil.custody.signing import generate_keypair

    mod = _load_tool()
    engine_report = _report_dict([_finding("a")])
    engine_pub = engine_report["hardened"][0]["signed_receipt"]["public_key_pem"]
    attacker_priv, _ = generate_keypair()
    wiped = {
        "hardened": [],
        "anchor": merkle.mint_anchor(
            merkle.merkle_root([]), "a" * 64, 0, attacker_priv
        ),
    }
    path = _write(tmp_path, wiped)
    # No trusted key: passes, but message discloses the limitation.
    code, msg = mod.verify(path)
    assert code == 0
    assert "intact" not in msg.lower()
    assert "wiped" in msg.lower() or "clean run" in msg.lower()
    # With the engine's trusted key: the attacker's anchor is rejected.
    code2, msg2 = mod.verify(path, trusted_pubkey_pem=engine_pub)
    assert code2 == 1
    assert "trusted" in msg2.lower() or "provenance" in msg2.lower()


# --- Round-3 robustness: malformed input returns an exit code, never raises ----


@pytest.mark.parametrize(
    "report",
    [
        [],  # top-level JSON array
        "not-an-object",  # top-level JSON string
    ],
)
def test_top_level_non_object_is_exit_2_not_crash(tmp_path, report):
    mod = _load_tool()
    code, _msg = mod.verify(_write(tmp_path, report))
    assert code == 2


def test_non_dict_anchor_is_rejected_not_crash(tmp_path):
    mod = _load_tool()
    report = _report_dict([_finding("a")])
    report["anchor"] = "not-a-dict"
    code, msg = mod.verify(_write(tmp_path, report))
    assert code == 1
    assert "anchor" in msg.lower()


def test_non_dict_entry_is_rejected_not_crash(tmp_path):
    mod = _load_tool()
    code, msg = mod.verify(_write(tmp_path, {"hardened": ["not-a-dict"]}))
    assert code == 1


def test_non_dict_receipt_is_rejected_not_crash(tmp_path):
    mod = _load_tool()
    report = {"hardened": [{"finding": {}, "signed_receipt": 7}]}
    code, msg = mod.verify(_write(tmp_path, report))
    assert code == 1


# --- Round-3 HIGH: cross-image splice masked by a None/"" image collision ------


@pytest.mark.parametrize("masked_image", [None, ""])
def test_cross_image_splice_masked_by_none_or_empty_is_rejected(tmp_path, masked_image):
    """Round-3 HIGH: two receipts from different images, re-signed under one key
    with image=None (or "") so they collapse to a single set element, must NOT
    bypass the single-image check. The engine only ever emits a 64-hex image, so
    a non-hex image is malformed and rejected.

    Note: with receipts present this exercises BOTH the per-receipt image guard
    and the anchor image guard (defense-in-depth); the empty-set test below
    uniquely exercises the anchor guard alone.
    """
    from sift_find_evil.custody import merkle
    from sift_find_evil.custody.signing import generate_keypair, sign_finding

    mod = _load_tool()
    priv, _ = generate_keypair()
    f_a = _finding("A")
    f_b = _finding("B")
    ra = sign_finding(f_a.to_dict(), priv, masked_image, "engine")
    rb = sign_finding(f_b.to_dict(), priv, masked_image, "engine")
    anchor = merkle.mint_anchor(
        merkle.merkle_root([ra["finding_hash"], rb["finding_hash"]]),
        masked_image,
        2,
        priv,
    )
    report = {
        "hardened": [
            {"finding": f_a.to_dict(), "signed_receipt": ra},
            {"finding": f_b.to_dict(), "signed_receipt": rb},
        ],
        "anchor": anchor,
    }
    code, msg = mod.verify(_write(tmp_path, report))
    assert code == 1
    assert "image" in msg.lower()


def test_anchor_with_none_image_on_empty_set_is_rejected(tmp_path):
    """An empty-set anchor must still carry a well-formed image, or a junk-image
    anchor slips through the empty-set path.

    Uniquely guards the anchor image check: with zero receipts the per-receipt
    image guard never runs, so ONLY the anchor guard can catch this - neutering
    the anchor guard makes this test go red on its own.
    """
    from sift_find_evil.custody import merkle
    from sift_find_evil.custody.signing import generate_keypair

    mod = _load_tool()
    priv, _ = generate_keypair()
    report = {
        "hardened": [],
        "anchor": merkle.mint_anchor(merkle.merkle_root([]), None, 0, priv),
    }
    code, msg = mod.verify(_write(tmp_path, report))
    assert code == 1
    assert "image" in msg.lower()
