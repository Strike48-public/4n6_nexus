#!/usr/bin/env python3
"""Standalone offline verifier for 4n6 Nexus finding receipts + run anchor.

Companion to ``tools/verify_chain.py`` (which verifies the audit hash-chain).
This one verifies the FINDING receipts in a hardening report:

  * every finding's publicly-verifiable Ed25519 receipt (the finding body still
    hashes to the receipt's bound identity, and the Ed25519 signature over
    finding-hash+image+tool checks out under the embedded public key), and
  * the run anchor: the Merkle root recomputed over the findings equals the
    root the anchor signed, and the anchor's Ed25519 signature is valid.

Like ``verify_chain.py`` it is DELIBERATELY self-contained: it imports nothing
from ``sift_find_evil`` and re-implements canonical JSON, the finding hash, and
the RFC 6962 Merkle tree from the Python standard library. That gives a third
party (a court, an auditor, a downstream consumer) two properties the in-product
verifier cannot:

  * Independent verification (Daubert): check the receipts + anchor with no
    shared secret and without installing our engine. With the engine's published
    public key supplied as a trust root, this proves PROVENANCE (the engine's
    key, for a specific evidence image); without it, it proves only that one
    keyholder signed the whole set (internal consistency). See the trust model.
  * Drift detection: if the product's writer and this reader ever disagree about
    canonicalization or the Merkle construction, a pristine report fails here.

The only non-stdlib dependency is ``cryptography`` for Ed25519 verification
(receipts are Ed25519 by design). If it is unavailable the tool exits 2 with a
clear message rather than silently passing.

Trust model (important): the receipts embed the signer's public key. Checking a
signature against a key from the SAME report proves only that one keyholder
signed the whole set (internal consistency) - NOT who that keyholder is. To prove
PROVENANCE (the engine emitted this, not an attacker who re-signed a doctored
set), pass the engine's out-of-band published public key as a trusted root; the
tool then requires every receipt and the anchor to be signed by exactly that key.
Regardless of a trusted key, the tool enforces set-level integrity: a SINGLE
signer and a SINGLE evidence image across all receipts + the anchor, and the
PRESENCE of an anchor whenever receipts exist. Each receipt's and the anchor's
``image_sha256`` must be a 64-hex digest (the engine's form); None/""/non-hex is
rejected as malformed, so a splice cannot be masked by setting every image to a
value that collapses in a set. So every PARTIAL-tamper splice - one that leaves
at least one genuine receipt behind - is caught even without a trusted key: drop
a finding and re-anchor with a fresh key, strip the anchor entirely, or mix
receipts from two runs/images. The one splice this cannot catch unaided is a
TOTAL wipe (zero findings left) then re-anchor: no receipt survives to pin the
signer/image, so it is indistinguishable from a genuinely clean run without a
trusted key. The tool says exactly that (rather than claiming the set is intact),
and supplying the engine's trusted public key closes even this case.

Usage:
    python3 tools/verify_receipts.py <report.json> [trusted_public_key.pem]
    # trusted key may also be given as $SFE_RECEIPT_TRUSTED_PUBKEY (a PEM path).
    # Reads findings from either a hardening report ("hardened") or a live
    # orchestrator report ("case_findings").

Exit codes (semantic):
    0  all receipts and the anchor verified (or report has no findings)
    1  a receipt/anchor failed, signers disagree, or provenance != trusted key
    2  file / environment error   (missing file, bad JSON, no cryptography)
    3  report is HMAC-only (no Ed25519 receipts) - not publicly verifiable here

Canonicalization rule (must match sift_find_evil/canonical.canonical_bytes):
    json.dumps(obj, sort_keys=True, separators=(",",":"), default=str).encode()
RFC 6962 Merkle (must match sift_find_evil/custody/merkle):
    leaf  = sha256(0x00 || finding_hash_bytes)
    node  = sha256(0x01 || left || right)
    empty = sha256(b"")
"""

from __future__ import annotations

import hashlib
import json
import sys


def _canonical(payload: object) -> bytes:
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), default=str
    ).encode("utf-8")


def _finding_hash(finding: dict) -> str:
    return hashlib.sha256(_canonical(finding)).hexdigest()


def _receipt_message(finding_hash: str, image_sha256: str, tool: str) -> bytes:
    """The exact bytes an Ed25519 finding receipt is signed over."""
    return _canonical(
        {"finding_hash": finding_hash, "image_sha256": image_sha256, "tool": tool}
    )


def _anchor_message(merkle_root: str, image_sha256: str, finding_count: int) -> bytes:
    """The exact bytes the run anchor is signed over."""
    return _canonical(
        {
            "merkle_root": merkle_root,
            "image_sha256": image_sha256,
            "finding_count": finding_count,
        }
    )


def _leaf_hash(finding_hash: str) -> bytes:
    return hashlib.sha256(b"\x00" + bytes.fromhex(finding_hash)).digest()


def _node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def _merkle_root(finding_hashes: list[str]) -> str:
    """RFC 6962 Merkle tree hash over the ordered finding hashes (hex)."""
    if not finding_hashes:
        return hashlib.sha256(b"").hexdigest()
    level = [_leaf_hash(fh) for fh in finding_hashes]
    while len(level) > 1:
        nxt: list[bytes] = []
        for i in range(0, len(level), 2):
            if i + 1 < len(level):
                nxt.append(_node_hash(level[i], level[i + 1]))
            else:
                nxt.append(level[i])
        level = nxt
    return level[0].hex()


def _verify_ed25519(public_key_pem: str, signature_hex: str, message: bytes) -> bool:
    """Return True iff the Ed25519 signature over ``message`` checks out.

    Uses only the supplied public key. Returns False (never raises) on malformed
    key/signature or a bad signature.
    """
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import serialization

    try:
        public_key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
        public_key.verify(bytes.fromhex(signature_hex), message)
        return True
    except (ValueError, TypeError, AttributeError, InvalidSignature):
        return False


def _normalize_pubkey(public_key_pem: str) -> str | None:
    """Return a canonical DER-hex form of a PEM public key, or None if invalid.

    Comparing normalized DER (not raw PEM text) makes the single-signer and
    trusted-key checks robust to incidental PEM whitespace/line-wrap differences.
    """
    from cryptography.hazmat.primitives import serialization

    try:
        key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
        return key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).hex()
    except (ValueError, TypeError, AttributeError):
        return None


def _is_image_sha(value: object) -> bool:
    """True iff ``value`` is a 64-char lowercase-hex SHA-256 (the engine's form).

    Rejecting None/""/non-hex is what stops a cross-image splice from being
    masked by setting every receipt's image to a value that collides in a set.
    """
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(c in "0123456789abcdef" for c in value)
    )


def _findings_section(report: dict) -> list:
    """Return the findings list from either report shape.

    A hardening report keys them under ``hardened``; the live orchestrator report
    keys them under ``case_findings``. Both use ``{finding, signed_receipt}``
    per entry, so downstream logic is identical.
    """
    if isinstance(report.get("hardened"), list):
        return report["hardened"]
    if isinstance(report.get("case_findings"), list):
        return report["case_findings"]
    return []


def verify(path: str, trusted_pubkey_pem: str | None = None) -> tuple[int, str]:
    """Return (exit_code, human_message) for the report at ``path``.

    Args:
        path: The report JSON (hardening report or live orchestrator report).
        trusted_pubkey_pem: Optional PEM text of the engine's published public
            key. When given, every receipt and the anchor MUST be signed by it
            (provenance). When None, the tool still enforces that all receipts +
            the anchor share ONE signer (internal consistency), and says so.
    """
    try:
        from cryptography.hazmat.primitives import serialization  # noqa: F401
    except ImportError:
        return (2, "environment error: the 'cryptography' package is required")

    try:
        with open(path, "r", encoding="utf-8") as f:
            report = json.load(f)
    except FileNotFoundError:
        return (2, f"file error: {path} not found")
    except (OSError, ValueError) as exc:
        return (2, f"file error: {exc}")

    if not isinstance(report, dict):
        return (2, "file error: report is not a JSON object")

    trusted_der = None
    if trusted_pubkey_pem is not None:
        trusted_der = _normalize_pubkey(trusted_pubkey_pem)
        if trusted_der is None:
            return (2, "environment error: trusted public key is not a valid PEM")

    entries = _findings_section(report)

    # HMAC-only reports carry no Ed25519 receipts; they are verifiable via
    # tools/verify_chain.py + the run HMAC key, not publicly here. Exit 3 (not
    # "BROKEN") so an honest fallback report is not mistaken for tampering.
    if entries and all(
        isinstance(e, dict) and e.get("signed_receipt") is None for e in entries
    ):
        return (
            3,
            f"HMAC-ONLY: {len(entries)} finding(s) carry no Ed25519 receipt; "
            "not publicly verifiable here (use verify_chain.py + the run key)",
        )

    # 1) Each finding's Ed25519 receipt: hash binding + signature. Collect the
    #    signer AND the bound image of each so we can enforce, across the whole
    #    set, a single signer and a single evidence image.
    recomputed_hashes: list[str] = []
    signer_ders: set[str] = set()
    receipt_images: set[str] = set()
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            return (1, f"BROKEN at finding {index}: entry is not an object")
        finding = entry.get("finding")
        receipt = entry.get("signed_receipt")
        if not isinstance(receipt, dict):
            return (1, f"BROKEN at finding {index}: missing or malformed receipt")
        if not isinstance(finding, dict):
            return (1, f"BROKEN at finding {index}: missing finding body")

        bound_hash = receipt.get("finding_hash")
        if _finding_hash(finding) != bound_hash:
            return (
                1,
                f"BROKEN at finding {index}: finding body does not match its "
                "receipt hash (in-line edit)",
            )
        receipt_pem = receipt.get("public_key_pem", "")
        signer_der = _normalize_pubkey(receipt_pem)
        if signer_der is None:
            return (1, f"BROKEN at finding {index}: unreadable receipt public key")
        if trusted_der is not None and signer_der != trusted_der:
            return (
                1,
                f"BROKEN at finding {index}: receipt not signed by the trusted "
                "key (provenance check failed)",
            )
        receipt_image = receipt.get("image_sha256")
        # The engine always binds a 64-hex image SHA-256. Reject anything else
        # (None, "", non-hex): otherwise several receipts carrying image=None all
        # collapse to one set element and the single-image splice check below is
        # silently bypassed - an attacker re-signs a cross-image splice with
        # image=None on every receipt.
        # INDEPENDENT GUARD (not redundant with the anchor-image check at
        # "anchor image_sha256 is not a 64-hex digest" below): this one covers the
        # per-receipt path; the anchor check covers the empty-set path where no
        # receipt is present. Neither subsumes the other - keep both.
        if not _is_image_sha(receipt_image):
            return (
                1,
                f"BROKEN at finding {index}: receipt image_sha256 is not a "
                "64-hex digest (malformed or a masked cross-image splice)",
            )
        message = _receipt_message(bound_hash, receipt_image, receipt.get("tool"))
        if not _verify_ed25519(receipt_pem, receipt.get("signature", ""), message):
            return (
                1,
                f"BROKEN at finding {index}: Ed25519 receipt signature invalid "
                "(rebound image/tool, swapped key, or forged signature)",
            )
        recomputed_hashes.append(bound_hash)
        signer_ders.add(signer_der)
        receipt_images.add(receipt_image)

    if len(signer_ders) > 1:
        return (
            1,
            "BROKEN: receipts are signed by more than one key "
            "(a spliced set - findings from different runs/signers)",
        )
    if len(receipt_images) > 1:
        return (
            1,
            "BROKEN: receipts are bound to more than one evidence image "
            "(a spliced set - findings from different runs/images)",
        )

    # 2) Run anchor. The engine ALWAYS emits an anchor when Ed25519 receipts are
    #    present (even the empty set), so "receipts present but no anchor" is not
    #    a shape the engine produces - it is a tamper signature (drop a finding +
    #    strip the anchor to dodge the set-level check). Reject it.
    anchor = report.get("anchor")
    if anchor is None:
        if recomputed_hashes:
            return (
                1,
                "BROKEN: Ed25519 receipts present but no anchor "
                "(set-level binding stripped - a finding may have been dropped)",
            )
        # No receipts and no anchor: nothing to verify (a truly empty report).
        return (0, "OK: 0 receipt(s), no anchor - empty report")

    if not isinstance(anchor, dict):
        return (1, "BROKEN: anchor is not an object (malformed report)")

    anchor_der = _normalize_pubkey(anchor.get("public_key_pem", ""))
    if anchor_der is None:
        return (1, "BROKEN: unreadable anchor public key")
    if trusted_der is not None and anchor_der != trusted_der:
        return (1, "BROKEN: anchor not signed by the trusted key (provenance)")
    # The anchor MUST be signed by the same key that signed the receipts, or a
    # dropped-finding-then-re-anchor-with-a-new-key splice would pass.
    if signer_ders and anchor_der not in signer_ders:
        return (
            1,
            "BROKEN: anchor signer differs from the receipt signer "
            "(set re-anchored with a different key)",
        )
    # The anchor's image must be a well-formed digest (same rejection of
    # None/""/non-hex as receipts). INDEPENDENT GUARD from the per-receipt check
    # above: on the empty-set path there are NO receipts, so only this check
    # stops a junk-image anchor. Both are load-bearing; keep both.
    anchor_image = anchor.get("image_sha256")
    if not _is_image_sha(anchor_image):
        return (
            1,
            "BROKEN: anchor image_sha256 is not a 64-hex digest " "(malformed report)",
        )
    # ...it MUST bind the same evidence image the receipts do, or receipts from
    # image A could ride under an anchor for image B (cross-image splice).
    if receipt_images and anchor_image not in receipt_images:
        return (
            1,
            "BROKEN: anchor image_sha256 differs from the receipts' image "
            "(cross-image splice)",
        )

    recomputed_root = _merkle_root(recomputed_hashes)
    if recomputed_root != anchor.get("merkle_root"):
        return (
            1,
            "BROKEN: recomputed Merkle root does not match the anchor "
            "(a finding was added, dropped, or reordered)",
        )
    if anchor.get("finding_count") != len(recomputed_hashes):
        return (
            1,
            "BROKEN: anchor finding_count does not match the receipts present",
        )
    anchor_msg = _anchor_message(
        anchor.get("merkle_root"),
        anchor.get("image_sha256"),
        anchor.get("finding_count"),
    )
    if not _verify_ed25519(
        anchor.get("public_key_pem", ""), anchor.get("signature", ""), anchor_msg
    ):
        return (1, "BROKEN: anchor Ed25519 signature invalid")

    n = len(recomputed_hashes)
    trust = (
        "provenance verified against trusted key"
        if trusted_der is not None
        else "single-signer consistency (no trusted key given - provenance NOT proven)"
    )
    # An empty set carries no receipts to pin the signer/image, so without a
    # trusted key a wipe-and-re-anchor cannot be distinguished from a genuinely
    # clean run. Say so rather than claiming "finding set intact".
    if n == 0 and trusted_der is None:
        return (
            0,
            "OK: empty finding set + anchor verified; note: with no receipts and "
            "no trusted key, a wiped set cannot be distinguished from a clean run "
            "(supply the engine's public key to confirm provenance)",
        )
    return (0, f"OK: {n} receipt(s) + anchor verified, finding set intact; {trust}")


def _load_trusted_pubkey(argv: list[str]) -> str | None:
    """Read the trusted public-key PEM from argv[2] or the env, if provided."""
    import os

    pem_path = (
        argv[2]
        if len(argv) >= 3
        else os.environ.get("SFE_RECEIPT_TRUSTED_PUBKEY", "").strip()
    )
    if not pem_path:
        return None
    with open(pem_path, "r", encoding="utf-8") as handle:
        return handle.read()


def main(argv: list[str]) -> int:
    if len(argv) not in (2, 3):
        print(
            "usage: verify_receipts.py <report.json> [trusted_public_key.pem]",
            file=sys.stderr,
        )
        return 2
    try:
        trusted = _load_trusted_pubkey(argv)
    except OSError as exc:
        print(f"file error: cannot read trusted public key: {exc}", file=sys.stderr)
        return 2
    code, message = verify(argv[1], trusted_pubkey_pem=trusted)
    stream = sys.stdout if code == 0 else sys.stderr
    print(message, file=stream)
    if code != 0:
        # Echo to stdout too so callers capturing stdout see the reason.
        print(message)
    return code


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
