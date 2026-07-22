"""Tests: approval signatures are real keyed integrity, not security theater.

SFE-jlce. The prior scheme stored a truncated *keyless* SHA-256 that was
(1) never re-verified, (2) computed over a throwaway datetime distinct from
the one persisted (unverifiable by construction), and (3) forgeable by anyone
with write access to findings.json. This suite pins the corrected behavior:

  - No signing key configured  -> no signature is fabricated (honest None).
  - Key configured             -> HMAC-SHA256 over the canonical decision.
  - verify() recomputes over the STORED timestamp/finding and compares in
    constant time, so any tamper (content, status, reviewer, reason, or a
    signature copied between findings) is detected.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from sift_find_evil.approval.manager import ApprovalManager

pytestmark = pytest.mark.unit

KEY = b"unit-test-approval-key"


def _write_draft_findings(path, finding_ids=("f1",)):
    """Write a findings.json with draft findings in the on-disk envelope."""
    path.write_text(
        json.dumps(
            {
                "findings": [
                    {
                        "finding_id": fid,
                        "finding": {"title": f"title-{fid}", "severity": "high"},
                        "approval": None,
                        "created_at": datetime.now(timezone.utc).isoformat(),
                    }
                    for fid in finding_ids
                ]
            }
        )
    )


def _mutate_on_disk(path, mutate):
    """Load findings.json, apply mutate(data), write it back (simulates tamper)."""
    data = json.loads(path.read_text())
    mutate(data)
    path.write_text(json.dumps(data))


class TestSigning:
    def test_approve_without_key_produces_no_signature(self, tmp_path):
        findings_path = tmp_path / "findings.json"
        _write_draft_findings(findings_path)
        mgr = ApprovalManager(findings_path=findings_path)  # no key

        mgr.approve(["f1"], reviewer="analyst", reason="looks real")

        approved = mgr.load_findings()[0]
        # Honest: unkeyed => unsigned, not a fabricated tamper-proof-looking hash.
        assert approved.approval.signature_hash is None

    def test_approve_with_key_produces_full_hmac(self, tmp_path):
        findings_path = tmp_path / "findings.json"
        _write_draft_findings(findings_path)
        mgr = ApprovalManager(findings_path=findings_path, secret_key=KEY)

        mgr.approve(["f1"], reviewer="analyst", reason="looks real")

        sig = mgr.load_findings()[0].approval.signature_hash
        # Full HMAC-SHA256 hex digest (64 chars), not truncated to 16.
        assert sig is not None
        assert len(sig) == 64
        assert all(c in "0123456789abcdef" for c in sig)

    def test_reject_with_key_is_signed(self, tmp_path):
        findings_path = tmp_path / "findings.json"
        _write_draft_findings(findings_path)
        mgr = ApprovalManager(findings_path=findings_path, secret_key=KEY)

        mgr.reject(["f1"], reviewer="analyst", reason="false positive")

        assert mgr.load_findings()[0].approval.signature_hash is not None


class TestVerify:
    def test_untampered_findings_verify(self, tmp_path):
        findings_path = tmp_path / "findings.json"
        _write_draft_findings(findings_path)
        mgr = ApprovalManager(findings_path=findings_path, secret_key=KEY)
        mgr.approve(["f1"], reviewer="analyst", reason="looks real")

        results = mgr.verify()

        assert results["total"] == 1
        assert results["verified"] == 1
        assert results["failed"] == 0

    def test_signature_binds_stored_timestamp(self, tmp_path):
        # The core defect: signing must use the persisted timestamp. If it were
        # a separate datetime.now() call, verify() over the stored timestamp
        # could never reproduce the digest -> this would fail.
        findings_path = tmp_path / "findings.json"
        _write_draft_findings(findings_path)
        mgr = ApprovalManager(findings_path=findings_path, secret_key=KEY)
        mgr.approve(["f1"], reviewer="analyst", reason="looks real")

        assert mgr.verify()["verified"] == 1

    def test_tampered_finding_content_is_detected(self, tmp_path):
        findings_path = tmp_path / "findings.json"
        _write_draft_findings(findings_path)
        mgr = ApprovalManager(findings_path=findings_path, secret_key=KEY)
        mgr.approve(["f1"], reviewer="analyst", reason="looks real")

        _mutate_on_disk(
            findings_path,
            lambda d: d["findings"][0]["finding"].__setitem__("severity", "low"),
        )

        results = mgr.verify()
        assert results["failed"] == 1
        assert results["verified"] == 0
        assert results["details"][0]["status"] == "TAMPERED"

    def test_tampered_reviewer_is_detected(self, tmp_path):
        findings_path = tmp_path / "findings.json"
        _write_draft_findings(findings_path)
        mgr = ApprovalManager(findings_path=findings_path, secret_key=KEY)
        mgr.approve(["f1"], reviewer="analyst", reason="looks real")

        _mutate_on_disk(
            findings_path,
            lambda d: d["findings"][0]["approval"].__setitem__("reviewer", "mallory"),
        )

        assert mgr.verify()["failed"] == 1

    def test_signature_is_bound_to_finding_id(self, tmp_path):
        # A valid signature copied from one finding onto another must not verify.
        findings_path = tmp_path / "findings.json"
        _write_draft_findings(findings_path, finding_ids=("f1", "f2"))
        mgr = ApprovalManager(findings_path=findings_path, secret_key=KEY)
        mgr.approve(["f1", "f2"], reviewer="analyst", reason="looks real")

        loaded = mgr.load_findings()
        sig_f1 = next(f for f in loaded if f.finding_id == "f1").approval.signature_hash

        # Attacker replaces f2's finding body but pastes f1's valid signature.
        def swap(d):
            for item in d["findings"]:
                if item["finding_id"] == "f2":
                    item["finding"]["title"] = "attacker-controlled"
                    item["approval"]["signature_hash"] = sig_f1

        _mutate_on_disk(findings_path, swap)

        results = mgr.verify()
        assert results["failed"] == 1

    def test_wrong_key_fails_verification(self, tmp_path):
        findings_path = tmp_path / "findings.json"
        _write_draft_findings(findings_path)
        signer = ApprovalManager(findings_path=findings_path, secret_key=KEY)
        signer.approve(["f1"], reviewer="analyst", reason="looks real")

        # The correct key verifies; only the wrong key fails.
        assert signer.verify()["verified"] == 1

        verifier = ApprovalManager(
            findings_path=findings_path, secret_key=b"a-different-key"
        )
        assert verifier.verify()["failed"] == 1

    def test_malformed_signature_is_tampered_not_crash(self, tmp_path):
        # A crafted non-hex/non-ASCII signature_hash must be reported TAMPERED,
        # never crash the verifier (hmac.compare_digest raises on non-ASCII str).
        findings_path = tmp_path / "findings.json"
        _write_draft_findings(findings_path)
        mgr = ApprovalManager(findings_path=findings_path, secret_key=KEY)
        mgr.approve(["f1"], reviewer="analyst", reason="looks real")

        _mutate_on_disk(
            findings_path,
            lambda d: d["findings"][0]["approval"].__setitem__(
                "signature_hash", "not-hex-éé"
            ),
        )

        results = mgr.verify()
        assert results["tampered"] == 1
        assert results["verified"] == 0

    def test_verify_without_key_returns_error(self, tmp_path):
        findings_path = tmp_path / "findings.json"
        _write_draft_findings(findings_path)
        ApprovalManager(findings_path=findings_path, secret_key=KEY).approve(
            ["f1"], reviewer="analyst", reason="looks real"
        )

        # Verification is impossible without the key; say so, don't fake a pass.
        results = ApprovalManager(findings_path=findings_path).verify()
        assert "error" in results

    def test_verify_no_key_over_signed_findings_warns_downgrade(self, tmp_path):
        # Signed findings + no key = possible key loss/downgrade, not "never
        # signed". The error must call that out so tampering isn't assumed away.
        findings_path = tmp_path / "findings.json"
        _write_draft_findings(findings_path)
        ApprovalManager(findings_path=findings_path, secret_key=KEY).approve(
            ["f1"], reviewer="analyst", reason="looks real"
        )

        results = ApprovalManager(findings_path=findings_path).verify()
        assert "error" in results
        assert "signed" in results["error"].lower()

    def test_verify_no_key_no_signatures_plain_error(self, tmp_path):
        # No key AND nothing signed: the plain "configure a key" error, with no
        # false alarm about lost signatures.
        findings_path = tmp_path / "findings.json"
        _write_draft_findings(findings_path)
        ApprovalManager(findings_path=findings_path).approve(  # unsigned
            ["f1"], reviewer="analyst", reason="looks real"
        )

        results = ApprovalManager(findings_path=findings_path).verify()
        assert "error" in results
        assert "signed findings" not in results["error"].lower()

    def test_unsigned_approved_finding_reported_not_verified(self, tmp_path):
        findings_path = tmp_path / "findings.json"
        _write_draft_findings(findings_path)
        # Approve with NO key -> signature is None (unsigned).
        ApprovalManager(findings_path=findings_path).approve(
            ["f1"], reviewer="analyst", reason="looks real"
        )

        # A verifier that DOES have a key must not count an unsigned finding as
        # verified; it is surfaced as unsigned.
        results = ApprovalManager(findings_path=findings_path, secret_key=KEY).verify()
        assert results["unsigned"] == 1
        assert results["verified"] == 0
        assert results["details"][0]["status"] == "UNSIGNED"


class TestKeyFromEnv:
    def test_key_read_from_environment(self, tmp_path, monkeypatch):
        monkeypatch.setenv("SFE_APPROVAL_HMAC_KEY", "env-supplied-key")
        findings_path = tmp_path / "findings.json"
        _write_draft_findings(findings_path)

        mgr = ApprovalManager(findings_path=findings_path)  # picks up env key
        mgr.approve(["f1"], reviewer="analyst", reason="looks real")

        assert mgr.load_findings()[0].approval.signature_hash is not None
        assert mgr.verify()["verified"] == 1

    def test_empty_env_key_is_treated_as_no_key(self, tmp_path, monkeypatch):
        monkeypatch.setenv("SFE_APPROVAL_HMAC_KEY", "")
        findings_path = tmp_path / "findings.json"
        _write_draft_findings(findings_path)

        mgr = ApprovalManager(findings_path=findings_path)
        mgr.approve(["f1"], reviewer="analyst", reason="looks real")

        assert mgr.load_findings()[0].approval.signature_hash is None
