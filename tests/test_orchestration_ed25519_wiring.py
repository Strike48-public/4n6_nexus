"""Ed25519 public-key receipts + Merkle anchor are wired into the LIVE path.

The scored recall path (hardening.py) makes Ed25519 the default; this proves the
multi-agent orchestrator - the OTHER emission path - does too, so the "publicly
verifiable by default" claim holds on both paths a hostile reviewer checks (not
just the harness). Every emitted finding carries a self-verifiable Ed25519
receipt, and the report binds the whole set with a signed Merkle anchor.

RED-first: the orchestrator minted HMAC-only receipts and had no anchor.
"""

import pytest

from sift_find_evil.custody import merkle
from sift_find_evil.custody.signing import CRYPTOGRAPHY_AVAILABLE, verify_finding
from sift_find_evil.orchestration import InvestigationOrchestrator

pytestmark = pytest.mark.skipif(
    not CRYPTOGRAPHY_AVAILABLE, reason="cryptography not installed"
)


@pytest.fixture
def run(tmp_path):
    audit_path = tmp_path / "audit.jsonl"
    orch = InvestigationOrchestrator(case_id="INC-ED25519-001", audit_path=audit_path)
    report = orch.run_demo_investigation()
    return orch, report


def test_every_finding_carries_a_publicly_verifiable_receipt(run):
    _orch, report = run
    assert report["case_findings"], "demo must emit findings"
    for item in report["case_findings"]:
        sr = item["signed_receipt"]
        assert sr is not None and sr["algorithm"] == "ed25519"
        # Verifiable with ONLY the receipt - no run key, no shared secret.
        assert verify_finding(item["finding"], sr) is True


def test_report_carries_a_verifiable_anchor_over_the_set(run):
    _orch, report = run
    anchor = report["anchor"]
    assert anchor is not None
    assert anchor["image_sha256"] == report["integrity"]["image_sha256"]
    assert anchor["finding_count"] == len(report["case_findings"])
    assert merkle.verify_anchor(anchor) is True


def test_anchor_root_matches_the_emitted_findings(run):
    _orch, report = run
    hashes = [i["signed_receipt"]["finding_hash"] for i in report["case_findings"]]
    assert merkle.merkle_root(hashes) == report["merkle_root"]
    assert report["merkle_root"] == report["anchor"]["merkle_root"]


def test_tampered_finding_fails_its_public_receipt(run):
    _orch, report = run
    item = report["case_findings"][0]
    forged = {**item["finding"], "severity": "info", "title": "benign"}
    assert verify_finding(forged, item["signed_receipt"]) is False


def test_dropping_a_finding_breaks_the_anchor_root(run):
    _orch, report = run
    if len(report["case_findings"]) < 2:
        pytest.skip("need >=2 findings to test set-level tamper")
    kept = [i["signed_receipt"]["finding_hash"] for i in report["case_findings"][:-1]]
    assert merkle.merkle_root(kept) != report["anchor"]["merkle_root"]


def test_hmac_receipt_still_present_alongside_public_one(run):
    _orch, report = run
    item = report["case_findings"][0]
    assert item["receipt"]["signature"]  # HMAC (run key)
    assert item["signed_receipt"]["signature"]  # Ed25519 (public key)


def test_standalone_receipt_verifier_agrees_on_the_live_report(run, tmp_path):
    """The offline tool must verify the orchestrator report AS EMITTED - no hand
    reshaping. Guards HIGH #2: previously the tool only read 'hardened' and
    raised a false BROKEN on the live 'case_findings' shape.
    """
    import json
    import subprocess
    import sys
    from pathlib import Path

    _orch, report = run
    report_path = tmp_path / "case_report.json"
    # Write the report exactly as the orchestrator produced it (case_findings +
    # anchor), serialized the same way a real run would persist it.
    report_path.write_text(
        json.dumps({k: report[k] for k in ("case_findings", "anchor", "merkle_root")}),
        encoding="utf-8",
    )
    tool = Path(__file__).resolve().parents[1] / "tools" / "verify_receipts.py"
    res = subprocess.run(
        [sys.executable, str(tool), str(report_path)],
        capture_output=True,
        text=True,
    )
    assert res.returncode == 0, res.stdout + res.stderr
