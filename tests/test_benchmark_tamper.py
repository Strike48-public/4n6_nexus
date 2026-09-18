"""Byte-flip tamper tests: the integrity path catches corruption (SFE-i7l7 PR2).

A benchmark that proves detection accuracy is only half the court-defensibility
story; the other half is proving the evidence trail is tamper-evident. The field's
leaders ship a byte-flip / tamper test: corrupt a sealed artifact and show that
verification FAILS. These tests exercise the two integrity primitives that ride
every investigation - the HMAC finding receipt and the audit hash-chain - and
prove a single-byte edit is caught.

Each test is a mutation guard by construction: the UNTAMPERED artifact verifies
True, and the one-byte edit flips it to False (or a broken chain). If verification
ever became a no-op, the tampered assertion would fail.
"""

from __future__ import annotations

import json

from sift_find_evil.audit.logger import AuditLogger
from sift_find_evil.audit.models import AgentMessage
from sift_find_evil.custody.receipt import mint_receipt, verify_receipt

KEY = b"k" * 32
IMAGE = "a" * 64


def _finding() -> dict:
    return {
        "title": "C2 to 203.0.113.66",
        "category": "command_and_control",
        "evidence": {"dst_ip": "203.0.113.66"},
    }


def test_untampered_receipt_verifies_true():
    # Baseline: a freshly minted receipt verifies over its own finding.
    finding = _finding()
    receipt = mint_receipt(finding, KEY, IMAGE, tool="engine")
    assert verify_receipt(finding, receipt, KEY) is True


def test_byte_flip_in_finding_fails_receipt_verification():
    # Tamper: flip one character in the finding's asserted anchor. The receipt was
    # minted over the original, so re-verification must FAIL - a post-hoc edit
    # cannot keep a receipt that still verifies.
    finding = _finding()
    receipt = mint_receipt(finding, KEY, IMAGE, tool="engine")
    tampered = json.loads(json.dumps(finding))
    tampered["evidence"]["dst_ip"] = "203.0.113.67"  # one byte: 66 -> 67
    assert verify_receipt(tampered, receipt, KEY) is False


def test_byte_flip_in_receipt_signature_fails_verification():
    # Tamper the receipt itself: flip one hex char of the signature.
    finding = _finding()
    receipt = mint_receipt(finding, KEY, IMAGE, tool="engine")
    sig = receipt["signature"]
    flipped = ("0" if sig[0] != "0" else "1") + sig[1:]
    receipt = {**receipt, "signature": flipped}
    assert verify_receipt(finding, receipt, KEY) is False


def test_wrong_key_fails_receipt_verification():
    # A receipt is bound to its per-run key: verifying under a different key fails.
    finding = _finding()
    receipt = mint_receipt(finding, KEY, IMAGE, tool="engine")
    assert verify_receipt(finding, receipt, b"x" * 32) is False


def _write_chain(logger: AuditLogger, n: int) -> None:
    for i in range(n):
        logger.log_agent_message(
            AgentMessage(sender="a", recipient="b", message_type="note", body={"i": i}),
            correlation_id="corr-tamper",
            agent="a",
        )


def test_untampered_audit_chain_verifies(tmp_path):
    logger = AuditLogger(tmp_path / "audit.jsonl")
    _write_chain(logger, 5)
    ok, broken_at, reason = logger.verify_chain()
    assert ok is True and broken_at is None


def test_byte_flip_in_audit_entry_breaks_the_chain(tmp_path):
    audit_path = tmp_path / "audit.jsonl"
    logger = AuditLogger(audit_path)
    _write_chain(logger, 5)
    # Tamper: flip a byte in the body of a middle entry. Its recomputed hash no
    # longer matches its stored hash, so the chain verify localizes the break.
    lines = audit_path.read_text().splitlines()
    rec = json.loads(lines[2])
    rec["details"]["body"]["i"] = 999
    lines[2] = json.dumps(rec)
    audit_path.write_text("\n".join(lines) + "\n")

    ok, broken_at, reason = logger.verify_chain()
    assert ok is False
    assert broken_at == 2
    assert reason
