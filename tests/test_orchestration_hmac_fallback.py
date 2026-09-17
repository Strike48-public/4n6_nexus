"""Orchestrator degrades to HMAC-only when cryptography is unavailable.

Guards invariant #2 on the LIVE path (the hardening path already has its own
fallback test): with the optional ``cryptography`` package absent, the
orchestrator must still run - no exception - minting HMAC receipts only, with no
Ed25519 signed receipt and no anchor. Without this, dropping the
``resolve_signing_key`` gate or calling ``sign_finding`` unconditionally would
break the core install and no test would go red.

This file has NO module-level crypto skip: it forces the crypto-absent path via
monkeypatch, so it runs and asserts the fallback regardless of whether the real
``cryptography`` package is installed.
"""

import sift_find_evil.custody.signing as signing
import sift_find_evil.orchestration as orchestration
from sift_find_evil.orchestration import InvestigationOrchestrator


def test_orchestrator_runs_hmac_only_without_cryptography(tmp_path, monkeypatch):
    # Simulate the core install (no connector extra) on both the resolver's view
    # and any downstream availability check.
    monkeypatch.setattr(signing, "CRYPTOGRAPHY_AVAILABLE", False)
    monkeypatch.setattr(orchestration, "resolve_signing_key", lambda: (None, False))

    audit_path = tmp_path / "audit.jsonl"
    orch = InvestigationOrchestrator(case_id="INC-NOCRYPTO-001", audit_path=audit_path)
    report = orch.run_demo_investigation()

    # No public-key signing available.
    assert orch.signing_key is None
    assert orch.signer_pinned is False
    assert report["anchor"] is None
    assert report["merkle_root"] is None

    # But findings still emit, each with a valid HMAC receipt (F1-safe path).
    assert report["case_findings"], "orchestrator must still emit findings"
    for item in report["case_findings"]:
        assert item["signed_receipt"] is None
        assert item["receipt"]["signature"]
        assert orch.receipt_minter.verify(item["finding"], item["receipt"]) is True
