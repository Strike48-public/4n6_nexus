"""Offline verification-tier verifier (tools/verify_verification.py) - SFE-xj7t.

Companion to tools/verify_receipts.py (receipts + anchor) and tools/verify_chain.py
(audit hash-chain). This one independently re-derives the ADVERSARIAL VERIFICATION
verdicts: for every finding, it re-runs the LLM-free entailment check (does each
asserted identity anchor actually appear, on a token boundary, in the raw evidence
span the detector consumed?) and the deterministic adjudicator ladder, then confirms
the verdict it re-derives matches the ``outcome`` / ``falsifier_status`` the engine
recorded.

Like the other two verifiers it is DELIBERATELY self-contained: it imports nothing
from ``sift_find_evil`` and re-implements the token-boundary entailment match and the
adjudication rules from the Python standard library. That is what makes the
verification tier a VERDICT-parity "5": the challenger is not only deterministic
(entailment re-derivation) and replayable (committed verdicts) but INDEPENDENTLY
re-runnable by a third party with no engine and no live model - the exact bar the
field's 5s clear via "LLM-free entailment + replay".

RED-first: before SFE-xj7t the hardening report recorded only the verdict
(``outcome``/``falsifier_status``/``falsifier_family``/``architectural_distance``)
and DISCARDED the re-derivation inputs (the asserted anchors, the evidence span,
the corroboration count), so no third party could reproduce the ruling offline.
These tests fail until (a) the report carries those inputs and (b) the standalone
tool exists.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

from sift_find_evil.findings import Finding, FindingCategory
from sift_find_evil.hardening import harden_findings

REPO_ROOT = Path(__file__).resolve().parents[1]
TOOL_PATH = REPO_ROOT / "tools" / "verify_verification.py"


def _load_tool():
    """Import the standalone verifier by path (it lives outside the package)."""
    spec = importlib.util.spec_from_file_location("verify_verification", TOOL_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _finding_with_anchor(title="beacon", dst_ip="10.0.0.9", sources=("netscan",)):
    """A finding that asserts a re-derivable identity anchor (an IP)."""
    return Finding(
        title=title,
        description="c2 beacon",
        finding_type="indicator",
        severity="high",
        category=FindingCategory.COMMAND_AND_CONTROL,
        evidence={"executable": "powershell.exe", "dst_ip": dst_ip},
        confidence=0.9,
        artifact_sources=list(sources),
    )


def _report_with_spans(findings, evidence_texts):
    """Harden findings, threading per-finding raw evidence spans (as the harness does)."""
    return harden_findings(
        findings,
        image_sha256="a" * 64,
        receipt_key=b"k" * 32,
        evidence_texts=evidence_texts,
    ).to_dict()


def _write(tmp_path, report) -> str:
    p = tmp_path / "hardening_report.json"
    p.write_text(json.dumps(report), encoding="utf-8")
    return str(p)


# --- the report must now CARRY the re-derivation inputs -------------------


def test_report_records_rederivation_inputs():
    """The adversarial entry must carry the anchors + evidence span + corroboration
    a third party needs to reproduce the ruling - not just the verdict."""
    f = _finding_with_anchor(dst_ip="10.0.0.9")
    report = _report_with_spans([f], {f.title: "connect to 10.0.0.9:443 established"})
    adv = report["hardened"][0]["adversarial"]
    # The verdict fields stay (unchanged contract)...
    assert "outcome" in adv and "falsifier_status" in adv
    # ...plus the re-derivation inputs (new, load-bearing for independence).
    assert adv.get("anchors"), "must record the asserted anchors re-derived"
    assert "evidence_span" in adv, "must record the raw evidence span checked"
    assert "corroboration" in adv, "must record the corroboration count adjudicated"


# --- the standalone tool exists and verifies a clean report ---------------


def test_tool_file_exists():
    assert TOOL_PATH.exists(), "tools/verify_verification.py must exist"


def test_clean_report_verifies_ok(tmp_path):
    mod = _load_tool()
    f = _finding_with_anchor(dst_ip="10.0.0.9")
    report = _report_with_spans([f], {f.title: "outbound to 10.0.0.9 seen"})
    code, msg = mod.verify(_write(tmp_path, report))
    assert code == 0, msg
    assert "OK" in msg


def test_missing_file_is_exit_2(tmp_path):
    mod = _load_tool()
    code, _msg = mod.verify(str(tmp_path / "nope.json"))
    assert code == 2


# --- mutation guards: the verdict must FOLLOW from the recorded evidence ---


def test_anchor_absent_from_span_makes_survived_unreproducible(tmp_path):
    """Core anti-Goodhart guard: if the recorded verdict is SURVIVED/sustained but
    the recorded evidence span does NOT contain the asserted anchor, re-derivation
    yields FALSIFIED - the recorded verdict is not reproducible, so the tool fails.
    Neuter this and a fabricated 'survived' verdict with no evidence passes."""
    mod = _load_tool()
    f = _finding_with_anchor(dst_ip="10.0.0.9", sources=("netscan", "pcap"))
    report = _report_with_spans([f], {f.title: "outbound to 10.0.0.9 seen"})
    adv = report["hardened"][0]["adversarial"]
    assert adv["outcome"] == "sustained", "precondition: a clean sustained verdict"
    # Tamper: blank the evidence span so the anchor 10.0.0.9 is no longer present,
    # but leave the recorded SURVIVED/sustained verdict in place.
    adv["evidence_span"] = "nothing to see here"
    code, msg = mod.verify(_write(tmp_path, report))
    assert code == 1
    assert "10.0.0.9" in msg or "reproduc" in msg.lower() or "falsif" in msg.lower()


def test_flipped_recorded_outcome_is_caught(tmp_path):
    """If someone edits the recorded outcome to disagree with what the recorded
    inputs re-derive, the tool must flag the mismatch."""
    mod = _load_tool()
    f = _finding_with_anchor(dst_ip="10.0.0.9")
    report = _report_with_spans([f], {f.title: "outbound to 10.0.0.9 seen"})
    adv = report["hardened"][0]["adversarial"]
    adv["outcome"] = "dismissed"  # re-derivation would not produce 'dismissed' here
    code, msg = mod.verify(_write(tmp_path, report))
    assert code == 1
    assert "outcome" in msg.lower() or "mismatch" in msg.lower()


def test_token_boundary_false_match_does_not_reproduce(tmp_path):
    """The entailment check is token-boundary aware: an anchor 10.0.0.9 that only
    appears embedded inside a larger token (10.0.0.99) is NOT entailed, so a
    recorded SURVIVED verdict against such a span must fail re-derivation."""
    mod = _load_tool()
    f = _finding_with_anchor(dst_ip="10.0.0.9", sources=("netscan", "pcap"))
    report = _report_with_spans([f], {f.title: "outbound to 10.0.0.9 seen"})
    adv = report["hardened"][0]["adversarial"]
    assert adv["outcome"] == "sustained"
    adv["evidence_span"] = (
        "outbound to 10.0.0.99 seen"  # embedded, not a boundary match
    )
    code, msg = mod.verify(_write(tmp_path, report))
    assert code == 1


def test_reads_orchestrator_case_findings_shape(tmp_path):
    """The tool must read a live orchestrator report (case_findings), not only a
    hardening report (hardened)."""
    mod = _load_tool()
    f = _finding_with_anchor(dst_ip="10.0.0.9")
    hardening = _report_with_spans([f], {f.title: "outbound to 10.0.0.9 seen"})
    orch_report = {"case_findings": hardening["hardened"]}
    code, msg = mod.verify(_write(tmp_path, orch_report))
    assert code == 0, msg


def test_top_level_non_object_is_exit_2_not_crash(tmp_path):
    mod = _load_tool()
    code, _msg = mod.verify(_write(tmp_path, ["not", "an", "object"]))
    assert code == 2


# --- null-falsifier (adjudication-consistent) path: legit shape + suppression guard


def test_null_falsifier_path_verifies_from_real_hardened_report(tmp_path):
    """A finding hardened WITHOUT a raw evidence span takes the engine's null-
    falsifier path (evidence_span=None, always SURVIVED). The verifier must accept
    this legitimate shape via the adjudication-consistent branch. Round-trips a
    REAL harden_findings report so the branch cannot silently drift or break."""
    mod = _load_tool()
    f = _finding_with_anchor(dst_ip="10.0.0.9", sources=("netscan", "pcap"))
    # No evidence_texts -> raw_evidence is None -> null-falsifier -> span None.
    report = harden_findings(
        [f], image_sha256="a" * 64, receipt_key=b"k" * 32
    ).to_dict()
    adv = report["hardened"][0]["adversarial"]
    assert adv["evidence_span"] is None, "precondition: null-falsifier path"
    assert adv["falsifier_status"] == "survived", "null falsifier always survives"
    code, msg = mod.verify(_write(tmp_path, report))
    assert code == 0, msg
    assert "adjudication-consistent" in msg


def test_forged_falsified_with_no_span_is_rejected_suppression_guard(tmp_path):
    """Anti-suppression guard: an attacker forges falsifier_status='falsified' +
    outcome='dismissed' + evidence_span=None to dismiss a genuine finding while
    dodging the entailment check. Because the null-falsifier ALWAYS survives, a
    non-survived status with no span is a shape the engine never emits, so the
    verifier must reject it. Neuter the null-path status check and this passes."""
    mod = _load_tool()
    f = _finding_with_anchor(dst_ip="10.0.0.9", sources=("netscan", "pcap"))
    report = harden_findings(
        [f], image_sha256="a" * 64, receipt_key=b"k" * 32
    ).to_dict()
    adv = report["hardened"][0]["adversarial"]
    assert adv["evidence_span"] is None
    # Forge a suppression: flip the SURVIVED/sustained verdict to a dismissal with
    # no evidence to contradict it.
    adv["falsifier_status"] = "falsified"
    adv["outcome"] = "dismissed"
    code, msg = mod.verify(_write(tmp_path, report))
    assert code == 1
    assert "span" in msg.lower() or "never emit" in msg.lower()
