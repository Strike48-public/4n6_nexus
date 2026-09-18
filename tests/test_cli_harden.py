"""CLI --harden wiring: route real-evidence findings through the custody chain.

The scored orchestrator/harness path already mints per-finding receipts + a
set-level Merkle anchor (SFE-cahy), but the real-evidence ``analyze`` CLI path
(cli.py:analyze_artifacts) wrote RAW findings only - so a real MFT/EVTX run
stopped two links short of the productionization chain the ranking dimension
demands: artifacts -> findings -> RECEIPTS -> VERIFIED report (SFE-13yw).

This wires ``analyze --harden`` to ``hardening.harden_findings`` and emits a
report the standalone offline verifier (tools/verify_receipts.py) consumes with
no glue. RED-first: ``_harden_report`` did not exist.

INVARIANT: detection output is untouched (harden_findings never mutates the
finding set), so F1 across the synthetic scenarios is unaffected - guarded by the
scenario harness, not here.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from types import SimpleNamespace

import pytest

from sift_find_evil.cli import (
    _EVIDENCE_PATH_ARGS,
    _harden_report,
    _hardened_report_path,
    _maybe_write_hardened,
)
from sift_find_evil.findings import Finding, FindingCategory

REPO_ROOT = Path(__file__).resolve().parent.parent
VERIFIER = REPO_ROOT / "tools" / "verify_receipts.py"


def _finding(title: str, actor: str = "evil.exe") -> Finding:
    return Finding(
        title=title,
        description="d",
        finding_type="indicator",
        severity="high",
        category=FindingCategory.EXECUTION,
        evidence={"executable": actor},
        confidence=0.9,
        artifact_sources=["mft"],
    )


def test_harden_report_shape_matches_hardening_to_dict() -> None:
    """The helper returns a HardeningReport.to_dict() the verifier understands."""
    findings = [_finding("a"), _finding("b")]
    report = _harden_report(findings, evidence_paths=[__file__], tool="engine")

    assert report["finding_count"] == 2
    assert isinstance(report["hardened"], list) and len(report["hardened"]) == 2
    # Every hardened entry pairs the finding body with its Ed25519 receipt.
    for entry in report["hardened"]:
        assert isinstance(entry["finding"], dict)
        assert entry["signed_receipt"] is not None
    # Set-level binding present by default (cryptography is installed in CI).
    assert report["anchor"] is not None
    assert report["merkle_root"]


def test_harden_report_binds_a_stable_evidence_digest() -> None:
    """image_sha256 is a real 64-hex content digest of the evidence, not a stub.

    Same evidence -> same digest across runs (receipts stay reproducible); the
    anchor and every receipt share that one image.
    """
    findings = [_finding("a")]
    r1 = _harden_report(findings, evidence_paths=[__file__], tool="engine")
    r2 = _harden_report(findings, evidence_paths=[__file__], tool="engine")

    image = r1["anchor"]["image_sha256"]
    assert len(image) == 64 and all(c in "0123456789abcdef" for c in image)
    assert r1["anchor"]["image_sha256"] == r2["anchor"]["image_sha256"]
    assert r1["hardened"][0]["signed_receipt"]["image_sha256"] == image


def test_harden_report_digest_is_bound_to_evidence_content(tmp_path: Path) -> None:
    """Different evidence bytes -> different image digest (not a constant stub).

    Mutation guard: an implementation that ignores the evidence and returns a
    fixed digest must turn this red - otherwise "bound to the evidence" is a lie.
    """
    a = tmp_path / "a.csv"
    b = tmp_path / "b.csv"
    a.write_text("EntryNumber,FileName\n1,alpha.exe\n", encoding="utf-8")
    b.write_text("EntryNumber,FileName\n1,beta.exe\n", encoding="utf-8")

    ra = _harden_report([_finding("x")], evidence_paths=[str(a)], tool="engine")
    rb = _harden_report([_finding("x")], evidence_paths=[str(b)], tool="engine")

    assert ra["anchor"]["image_sha256"] != rb["anchor"]["image_sha256"]


def test_harden_report_does_not_mutate_findings() -> None:
    """Hardening is additive - the caller's finding list/count is preserved."""
    findings = [_finding("a"), _finding("b"), _finding("c")]
    before = [f.title for f in findings]
    report = _harden_report(findings, evidence_paths=[__file__], tool="engine")
    assert [f.title for f in findings] == before
    assert report["finding_count"] == len(findings)


def test_hardened_report_verifies_offline(tmp_path: Path) -> None:
    """End-to-end: a --harden report passes the standalone offline verifier.

    This is the productionization chain in miniature: findings -> receipts +
    anchor -> independently re-verified by a tool that imports nothing from the
    engine (exit 0).
    """
    findings = [_finding("a"), _finding("b")]
    report = _harden_report(findings, evidence_paths=[__file__], tool="engine")
    report_path = tmp_path / "report.json"
    report_path.write_text(json.dumps(report, default=str), encoding="utf-8")

    proc = subprocess.run(
        [sys.executable, str(VERIFIER), str(report_path)],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, f"verifier rejected a pristine report: {proc.stderr}"
    assert "receipt(s) + anchor verified" in proc.stdout


def test_tampered_hardened_report_is_rejected_offline(tmp_path: Path) -> None:
    """Mutation guard: editing a finding body after hardening breaks verification.

    If this stays green when a finding is doctored, the receipts guard nothing.
    """
    findings = [_finding("a"), _finding("b")]
    report = _harden_report(findings, evidence_paths=[__file__], tool="engine")
    # In-line edit: change a finding body without re-signing its receipt.
    report["hardened"][0]["finding"]["title"] = "tampered"
    report_path = tmp_path / "tampered.json"
    report_path.write_text(json.dumps(report, default=str), encoding="utf-8")

    proc = subprocess.run(
        [sys.executable, str(VERIFIER), str(report_path)],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 1, "verifier accepted a tampered finding body"


def test_hardened_report_path_is_sibling_of_output() -> None:
    assert _hardened_report_path(Path("/cases/x/findings.json")) == Path(
        "/cases/x/findings.hardened.json"
    )


def test_maybe_write_hardened_noop_without_flag(tmp_path: Path) -> None:
    """No --harden -> no hardening report written (backward compatible)."""
    args = SimpleNamespace(harden=False, output=str(tmp_path / "findings.json"))
    _maybe_write_hardened(args, [_finding("a")])
    assert not (tmp_path / "findings.hardened.json").exists()


def test_maybe_write_hardened_emits_verifiable_report(tmp_path: Path) -> None:
    """--harden writes <output>.hardened.json that the offline verifier accepts."""
    output = tmp_path / "findings.json"
    # Only the evidence dests we actually set carry a value; the rest are None,
    # matching how argparse populates unset optional flags.
    kwargs = {name: None for name in _EVIDENCE_PATH_ARGS}
    kwargs["mft"] = __file__  # a real file so the image digest is non-empty
    args = SimpleNamespace(harden=True, output=str(output), **kwargs)

    _maybe_write_hardened(args, [_finding("a"), _finding("b")])

    hardened = tmp_path / "findings.hardened.json"
    assert hardened.exists()
    report = json.loads(hardened.read_text(encoding="utf-8"))
    # The report must reflect the findings passed in, not an empty/dropped set -
    # else "it verifies" is a vacuous pass on an empty anchor. (Mutation guard:
    # hardening [] instead of the real findings must turn this red.)
    assert report["finding_count"] == 2
    assert len(report["hardened"]) == 2
    assert all(h["signed_receipt"] is not None for h in report["hardened"])
    proc = subprocess.run(
        [sys.executable, str(VERIFIER), str(hardened)],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr


def test_harden_without_output_exits(tmp_path: Path) -> None:
    """cmd_analyze rejects --harden with no --output (the report has nowhere to go)."""
    from sift_find_evil.cli import cmd_analyze

    args = SimpleNamespace(
        harden=True,
        output=None,
        mft="m",
        prefetch="p",
        evtx="e",
    )
    with pytest.raises(SystemExit) as exc:
        cmd_analyze(args)
    assert exc.value.code == 1
